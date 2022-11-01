package main

import (
	"fmt"
	"log"
	"net/http"
)

type HandlerFunc = func(http.ResponseWriter, *http.Request) error

type Handler struct {
	Func        HandlerFunc
	Method      string
	ContentType string
}

func NewHtmlHandler(f HandlerFunc, method string) *Handler {
	return &Handler{f, method, "text/html; charset=utf-8"}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h.Method != "" && req.Method != h.Method {
		http.Error(w, "Unsupported method "+req.Method, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", h.ContentType)
	err := h.Func(w, req)
	if err == nil {
		return
	}
	const internal = http.StatusInternalServerError
	httpErr, ok := err.(HttpError)
	if !ok || httpErr.StatusCode() == internal {
		log.Println(err)
		http.Error(w, http.StatusText(internal), internal)
		return
	}
	http.Error(w, err.Error(), httpErr.StatusCode())
}

type HttpError interface {
	error
	StatusCode() int
}

type Error struct {
	Msg  string
	Code int
}

func (e *Error) Error() string { return e.Msg }

func (e *Error) StatusCode() int { return e.Code }

func NewError(code int) *Error {
	return &Error{http.StatusText(code), code}
}

func FormatError(code int, format string, a ...interface{}) *Error {
	return &Error{fmt.Sprintf(format, a...), code}
}
