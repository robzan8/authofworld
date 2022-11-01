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

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./server/static"))))
	http.Handle("/", NewHtmlHandler(rootHandler, http.MethodGet))
	http.Handle("/login", NewHtmlHandler(loginHandler, ""))
	http.Handle("/register", NewHtmlHandler(registerHandler, ""))
	http.Handle("/logout", NewHtmlHandler(logoutHandler, http.MethodGet))
	http.Handle("/create-certificates", NewHtmlHandler(createCertsHandler, http.MethodGet))
	http.Handle("/certificates", NewHtmlHandler(certsHandler, ""))
	http.Handle("/qrcode/", NewHtmlHandler(qrcodeHandler, http.MethodGet))

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func rootHandler(w http.ResponseWriter, req *http.Request) error {
	if req.URL.Path != "/" {
		return NewError(http.StatusNotFound)
	}
	var userData interface{}
	if u := LoggedUser(req); u != nil {
		userData = u
	}
	return masterTemplate.ExecuteTemplate(w, "index", userData)
}

func loginHandler(w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case http.MethodGet:
		return loginGet(w, req)
	case http.MethodPost:
		return loginPost(w, req)
	default:
		return FormatError(http.StatusBadRequest, "Unsupported method %s", req.Method)
	}
}

func loginGet(w http.ResponseWriter, req *http.Request) error {
	return masterTemplate.ExecuteTemplate(w, "login", nil)
}

func loginPost(w http.ResponseWriter, req *http.Request) error {
	email := req.FormValue("email")
	if email == "" {
		return FormatError(http.StatusUnauthorized, "No email provided")
	}
	password := req.FormValue("password")
	if password == "" {
		return FormatError(http.StatusUnauthorized, "No password provided")
	}
	user, err := FindUser(email)
	if err != nil {
		return err
	}
	if user == nil {
		return FormatError(http.StatusUnauthorized, "Invalid email or password")
	}
	hash := HashPassword(password)
	if hash != user.HashedPassword {
		return FormatError(http.StatusUnauthorized, "Invalid email or password")
	}
	s, err := CreateSession(user)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:    SessionCookieName,
		Value:   s.Id,
		Expires: s.Expires,
	})

	fmt.Fprintln(w, "Login was successful :)")
	return nil
}

func logoutHandler(w http.ResponseWriter, req *http.Request) error {
	cookie, err := req.Cookie(SessionCookieName)
	if err == nil && cookie != nil {
		DeleteSession(cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   SessionCookieName,
			MaxAge: -1,
		})
	}

	fmt.Fprintln(w, "Come back any time!")
	return nil
}

func createCertsHandler(w http.ResponseWriter, req *http.Request) error {
	user := LoggedUser(req)
	if user == nil {
		return FormatError(http.StatusUnauthorized, "You must be logged in to create certificates")
	}
	return masterTemplate.ExecuteTemplate(w, "create-certificates", nil)
}

func certsHandler(w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case http.MethodGet:
		return certsGet(w, req)
	case http.MethodPost:
		return certsPost(w, req)
	default:
		return FormatError(http.StatusBadRequest, "Unsupported method %s", req.Method)
	}
}

func certsGet(w http.ResponseWriter, req *http.Request) error {
	user := LoggedUser(req)
	if user == nil {
		return FormatError(http.StatusUnauthorized, "You must be logged in to see your certificates")
	}

	ctx := context.TODO()
	cur, err := certificates.Find(ctx, bson.D{{Key: "creator", Value: user.Email}})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	var certs []Certificate
	for cur.Next(ctx) {
		var c Certificate
		err := cur.Decode(&c)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}

	return masterTemplate.ExecuteTemplate(w, "certificates", certs)
}

func certsPost(w http.ResponseWriter, req *http.Request) error {
	user := LoggedUser(req)
	if user == nil {
		return FormatError(http.StatusUnauthorized, "Must be logged in with business account")
	}

	numCerts, err := strconv.Atoi(req.FormValue("numCerts"))
	if err != nil || numCerts < 1 || numCerts > 100 {
		return FormatError(http.StatusUnprocessableEntity, "numCerts must be an integer between 1 and 100")
	}
	desc := req.FormValue("description")
	if desc == "" {
		return FormatError(http.StatusUnprocessableEntity, "No product description provided")
	}

	err = CreateCertificates(numCerts, user.Email, desc)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "%d certificates created!", numCerts)
	return nil
}

func qrcodeHandler(w http.ResponseWriter, req *http.Request) error {
	if m, _ := path.Match("/qrcode/*", req.URL.Path); !m {
		return NewError(http.StatusNotFound)
	}
	user := LoggedUser(req)
	if user == nil {
		return FormatError(http.StatusUnauthorized, "You must be logged in")
	}
	_, certId := path.Split(req.URL.Path)
	var c Certificate
	err := certificates.FindOne(context.TODO(), bson.D{{Key: "_id", Value: certId}}).Decode(&c)
	if err == mongo.ErrNoDocuments {
		return NewError(http.StatusNotFound)
	}
	if err != nil {
		return err
	}
	if c.Creator != user.Email {
		return FormatError(http.StatusForbidden, "Only the creator can see the QRCode of a certificate")
	}

	return masterTemplate.ExecuteTemplate(w, "qrcode", certId)
}

func registerHandler(w http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case http.MethodGet:
		return registerGet(w, req)
	case http.MethodPost:
		return registerPost(w, req)
	default:
		return FormatError(http.StatusBadRequest, "Unsupported method %s", req.Method)
	}
}

func registerGet(w http.ResponseWriter, req *http.Request) error {
	return masterTemplate.ExecuteTemplate(w, "register", nil)
}

func registerPost(w http.ResponseWriter, req *http.Request) error {
	email := req.FormValue("email")
	if email == "" {
		return FormatError(http.StatusUnauthorized, "No email provided")
	}
	password := req.FormValue("password")
	if password == "" {
		return FormatError(http.StatusUnauthorized, "No password provided")
	}
	user, err := FindUser(email)
	if err != nil {
		return err
	}
	if user != nil {
		return FormatError(http.StatusUnprocessableEntity, "Email already in use")
	}
	user = &User{
		Email:          email,
		HashedPassword: HashPassword(password),
		Role:           "",
	}

	_, err = users.InsertOne(context.TODO(), user)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "User created :)")
	return nil
}
