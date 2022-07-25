package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var masterTemplate = template.New("master")

func loadTemplates(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		name := f.Name()
		ext := filepath.Ext(name)
		if f.IsDir() || ext != ".html" {
			continue
		}
		html, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		name = name[0 : len(name)-len(".html")]
		_, err = masterTemplate.New(name).Parse(string(html))
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("$PORT not set")
	}

	opt := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), opt)
	if err != nil {
		log.Fatalf("Error connecting to mongo: %s", err)
	}
	defer client.Disconnect(context.TODO())

	users = client.Database("authofworld").Collection("users")
	certificates = client.Database("authofworld").Collection("certificates")

	err = loadTemplates("server/templates")
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", http.FileServer(http.Dir("./server/static")))
	http.HandleFunc("/index", restrictMethod(indexHandler, http.MethodGet))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", restrictMethod(logoutHandler, http.MethodGet))
	http.HandleFunc("/create-certificates", restrictMethod(createCertsHandler, http.MethodGet))
	http.HandleFunc("/certificates", certsHandler)

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

type httpHandler = func(http.ResponseWriter, *http.Request)

func restrictMethod(handler httpHandler, method string) httpHandler {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method == method {
			handler(w, req)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Unsupported method %s", req.Method)
	}
}

func allowCrossOrigin(handler httpHandler) httpHandler {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if req.Method == http.MethodOptions {
			return // OK
		}
		handler(w, req)
	}
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	templateData := make(map[string]string)
	if u := LoggedUser(req); u != nil {
		templateData["userName"] = u.Email
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := masterTemplate.ExecuteTemplate(w, "index", templateData)
	if err != nil {
		log.Println(err)
	}
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		loginGet(w, req)
	case http.MethodPost:
		loginPost(w, req)
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Unsupported method %s", req.Method)
	}
}

func loginGet(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := masterTemplate.ExecuteTemplate(w, "login", nil)
	if err != nil {
		log.Println(err)
	}
}

func loginPost(w http.ResponseWriter, req *http.Request) {
	var err error // beware of shadowing
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, "%s", err)
		}
	}()

	email := req.FormValue("email")
	if email == "" {
		err = errors.New("No email provided")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		err = errors.New("No password provided")
		return
	}
	user, err := FindUser(email)
	if err != nil {
		log.Println(err)
		err = errors.New("Internal server error")
		return
	}
	if user == nil {
		err = errors.New("Invalid email or password")
		return
	}
	hash := HashPassword(password)
	if hash != user.HashedPassword {
		err = errors.New("Invalid email or password")
		return
	}
	s, err := CreateSession(user)
	if err != nil {
		log.Println(err)
		err = errors.New("Internal server error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   s.Id,
		Expires: s.Expires,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "Login was successful :)")
}

func logoutHandler(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie(SessionCookieName)
	if err == nil && cookie != nil {
		DeleteSession(cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   SessionCookieName,
			MaxAge: -1,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "Come back any time!")
}

func createCertsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	user := LoggedUser(req)
	if user == nil {
		fmt.Fprintln(w, "You must be logged in to create certificates")
		return
	}

	err := masterTemplate.ExecuteTemplate(w, "create-certificates", nil)
	if err != nil {
		log.Println(err)
	}
}

func certsHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		certsGet(w, req)
	case http.MethodPost:
		certsPost(w, req)
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Unsupported method %s", req.Method)
	}
}

func certsGet(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := masterTemplate.ExecuteTemplate(w, "certificates", nil)
	if err != nil {
		log.Println(err)
	}
}

func certsPost(w http.ResponseWriter, req *http.Request) {
	var err error // beware of shadowing
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, "%s", err)
		}
	}()

	user := LoggedUser(req)
	if user == nil {
		err = errors.New("Must be logged in with business account")
		return
	}

	numCerts, err := strconv.Atoi(req.FormValue("numCerts"))
	if err != nil || numCerts < 1 || numCerts > 100 {
		err = errors.New("numCerts must be an integer between 1 and 100")
		return
	}
	desc := req.FormValue("description")
	if desc == "" {
		err = errors.New("No product description provided")
		return
	}

	err = CreateCertificates(numCerts, user.Email, desc)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "%d certificates created!", numCerts)
}
