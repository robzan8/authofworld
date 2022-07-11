package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const SessionCookieName = "session"

// TODO: locality
// https://eager.io/blog/how-long-does-an-id-need-to-be/
func GenerateId() (string, error) {
	var b [12]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b[:]), nil
}

type User struct {
	Email          string
	HashedPassword string
}

func GetUser(email string) User {
	if email == "rolex@rolex.com" {
		return User{"rolex@rolex.com", HashPassword("hello")}
	}
	return User{}
}

type Session struct {
	Id      string
	Email   string
	Expires time.Time
}

// TODO: remove expired sessions and extend active sessions.
var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]Session) // maps session IDs to sessions
)

func HashPassword(p string) string {
	hash := sha256.Sum256([]byte(p))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// Security vulnerability here:
// A malicious client could keep logging-in and discarding session cookies,
// creating an unbound number of sessions on the server.
func CreateSession(email string) (Session, error) {
	id, err := GenerateId()
	if err != nil {
		return Session{}, err
	}
	var s Session
	s.Id = id
	s.Email = email
	s.Expires = time.Now().Add(8 * time.Hour)

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	sessions[id] = s
	return s, nil
}

func LookupSession(id string) Session {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	return sessions[id]
}

func DeleteSession(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	delete(sessions, id)
}

func LoggedUser(req *http.Request) (email string) {
	cookie, err := req.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return LookupSession(cookie.Value).Email
}
