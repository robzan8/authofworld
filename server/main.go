package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
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

	http.Handle("/assets/", http.StripPrefix("/assets/",
		http.FileServer(http.Dir("./server/assets"))))
	http.HandleFunc("/", restrictMethod(rootHandler, http.MethodGet))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", restrictMethod(logoutHandler, http.MethodGet))
	http.HandleFunc("/create-certificates", restrictMethod(createCertsHandler, http.MethodGet))
	http.HandleFunc("/certificates", certsHandler)
	http.HandleFunc("/qrcode/", restrictMethod(qrcodeHandler, http.MethodGet))

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

func setContentHtml(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func handleInternalErr(w http.ResponseWriter, err error) {
	log.Println(err)
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintln(w, "Internal server error")
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	var userData interface{}
	if u := LoggedUser(req); u != nil {
		userData = u
	}
	err := masterTemplate.ExecuteTemplate(w, "index", userData)
	if err != nil {
		handleInternalErr(w, err)
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
	setContentHtml(w)

	err := masterTemplate.ExecuteTemplate(w, "login", nil)
	if err != nil {
		handleInternalErr(w, err)
	}
}

func loginPost(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	email := req.FormValue("email")
	if email == "" {
		writeErr(w, http.StatusUnauthorized, "No email provided")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		writeErr(w, http.StatusUnauthorized, "No password provided")
		return
	}
	user, err := FindUser(email)
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	hash := HashPassword(password)
	if hash != user.HashedPassword {
		writeErr(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	s, err := CreateSession(user)
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   s.Id,
		Expires: s.Expires,
	})

	fmt.Fprintln(w, "Login was successful :)")
}

func logoutHandler(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	cookie, err := req.Cookie(SessionCookieName)
	if err == nil && cookie != nil {
		DeleteSession(cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   SessionCookieName,
			MaxAge: -1,
		})
	}

	fmt.Fprintln(w, "Come back any time!")
}

func createCertsHandler(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	user := LoggedUser(req)
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "You must be logged in to create certificates")
		return
	}

	err := masterTemplate.ExecuteTemplate(w, "create-certificates", nil)
	if err != nil {
		handleInternalErr(w, err)
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
	setContentHtml(w)

	user := LoggedUser(req)
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "You must be logged in to see your certificates")
		return
	}

	ctx := context.TODO()
	cur, err := certificates.Find(ctx, bson.D{{Key: "creator", Value: user.Email}})
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	defer cur.Close(ctx)
	var certs []Certificate
	for cur.Next(ctx) {
		var c Certificate
		err := cur.Decode(&c)
		if err != nil {
			handleInternalErr(w, err)
			return
		}
		certs = append(certs, c)
	}

	err = masterTemplate.ExecuteTemplate(w, "certificates", certs)
	if err != nil {
		handleInternalErr(w, err)
	}
}

func certsPost(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	user := LoggedUser(req)
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "Must be logged in with business account")
		return
	}

	numCerts, err := strconv.Atoi(req.FormValue("numCerts"))
	if err != nil || numCerts < 1 || numCerts > 100 {
		writeErr(w, http.StatusUnprocessableEntity,
			"numCerts must be an integer between 1 and 100")
		return
	}
	desc := req.FormValue("description")
	if desc == "" {
		writeErr(w, http.StatusUnprocessableEntity, "No product description provided")
		return
	}

	err = CreateCertificates(numCerts, user.Email, desc)
	if err != nil {
		handleInternalErr(w, err)
		return
	}

	fmt.Fprintf(w, "%d certificates created!", numCerts)
}

func qrcodeHandler(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	if m, _ := path.Match("/qrcode/*", req.URL.Path); !m {
		http.NotFound(w, req)
		return
	}
	user := LoggedUser(req)
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "You must be logged in")
		return
	}
	_, certId := path.Split(req.URL.Path)
	var c Certificate
	err := certificates.FindOne(context.TODO(), bson.D{{Key: "_id", Value: certId}}).Decode(&c)
	if err == mongo.ErrNoDocuments {
		http.NotFound(w, req)
		return
	}
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	if c.Creator != user.Email {
		writeErr(w, http.StatusForbidden,
			"Only the creator can see the QRCode of a certificate")
		return
	}

	err = masterTemplate.ExecuteTemplate(w, "qrcode", certId)
	if err != nil {
		handleInternalErr(w, err)
	}
}

func registerHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		registerGet(w, req)
	case http.MethodPost:
		registerPost(w, req)
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Unsupported method %s", req.Method)
	}
}

func registerGet(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	err := masterTemplate.ExecuteTemplate(w, "register", nil)
	if err != nil {
		handleInternalErr(w, err)
	}
}

func registerPost(w http.ResponseWriter, req *http.Request) {
	setContentHtml(w)

	email := req.FormValue("email")
	if email == "" {
		writeErr(w, http.StatusUnauthorized, "No email provided")
		return
	}
	password := req.FormValue("password")
	if password == "" {
		writeErr(w, http.StatusUnauthorized, "No password provided")
		return
	}
	user, err := FindUser(email)
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	if user != nil {
		writeErr(w, http.StatusUnprocessableEntity, "Email already in use")
		return
	}
	user = &User{
		Email:          email,
		HashedPassword: HashPassword(password),
		Role:           "",
	}

	_, err = users.InsertOne(context.TODO(), user)
	if err != nil {
		handleInternalErr(w, err)
		return
	}
	fmt.Fprintln(w, "User created :)")
}
