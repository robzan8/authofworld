package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

	err := loadTemplates("server/templates")
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", http.FileServer(http.Dir("./server/static")))
	http.HandleFunc("/index", restrictMethod(indexHandler, http.MethodGet))
	http.HandleFunc("/login", loginHandler)

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
	var err error // beware of shadowing
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, "%s", err)
		}
	}()

	t := masterTemplate.Lookup("index")
	if t == nil {
		err = errors.New("indexHandler: index template is undefined")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	err = t.Execute(w, map[string]string{"userName": ""})
	if err != nil {
		log.Println(err)
	}
}

func loginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {

	}

	var err error // beware of shadowing
	defer func() {
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, "%s", err)
		}
	}()

	senderAddr := req.FormValue("senderAddr")
	if senderAddr == "" {
		err = errors.New("No sender address provided")
		return
	}
	recipientAddr := req.FormValue("recipientAddr")
	if recipientAddr == "" {
		err = errors.New("No recipient address provided")
		return
	}
	subject := req.FormValue("subject")
	if subject == "" {
		err = errors.New("No subject provided")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "Your request has been accepted for processing :)")
}
