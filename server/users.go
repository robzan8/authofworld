package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var users *mongo.Collection

type User struct {
	Email          string `bson:"email"`
	HashedPassword string `bson:"hashedPassword"`
	Role           Role   `bson:"role"`
}

func HashPassword(p string) string {
	hash := sha256.Sum256([]byte(p))
	return base64.StdEncoding.EncodeToString(hash[:])
}

type Role string

const (
	Regular  Role = ""
	Business      = "business"
	Admin         = "admin"
)

func FindUser(email string) (*User, error) {
	user := new(User)
	err := users.FindOne(context.TODO(), bson.D{{"email", email}}).Decode(user)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// https://eager.io/blog/how-long-does-an-id-need-to-be/
func GenerateId() (string, error) {
	var b [12]byte

	n := time.Now().Unix()
	b[0] = byte((n >> 24) & 0xff)
	b[1] = byte((n >> 16) & 0xff)
	b[2] = byte((n >> 8) & 0xff)
	b[3] = byte(n & 0xff)

	_, err := rand.Read(b[4:])
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b[:]), nil
}

type Session struct {
	Id      string
	User    *User
	Expires time.Time
}

// TODO: remove expired sessions and extend active sessions.
var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]*Session) // maps session IDs to sessions
)

// Security vulnerability here:
// A malicious client could keep logging-in and discarding session cookies,
// creating an unbound number of sessions on the server.
func CreateSession(user *User) (*Session, error) {
	id, err := GenerateId()
	if err != nil {
		return nil, err
	}
	s := new(Session)
	s.Id = id
	s.User = user
	s.Expires = time.Now().Add(8 * time.Hour)

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	sessions[id] = s
	return s, nil
}

func LookupSession(id string) *Session {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	return sessions[id]
}

func DeleteSession(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	delete(sessions, id)
}

const SessionCookieName = "session"

func LoggedUser(req *http.Request) *User {
	cookie, err := req.Cookie(SessionCookieName)
	if err != nil {
		return nil
	}
	s := LookupSession(cookie.Value)
	if s == nil {
		return nil
	}
	return s.User
}
