package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

func GenerateUuid() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

type user struct {
	email          string
	hashedPassword string
}

func GetUser(email string) (user, error) {
	if email == "" {
		return user{}, errors.New("GetUser: no email")
	}
	if email == "rolex@rolex.com" {
		return user{"rolex@rolex.com", HashPassword("hello")}, nil
	}
	return user{}, errors.New("Invalid email or password")
}

type Session struct {
	Id      string
	Expires time.Time
}

// TODO: remove expired sessions and extend active sessions.
var (
	sessionsMu sync.Mutex
	sessions   map[string]Session // maps email to session
)

func HashPassword(p string) string {
	hash := sha256.Sum256([]byte(p))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func Login(email, password string) (Session, error) {
	user, err := GetUser(email)
	if err != nil {
		return Session{}, err
	}
	hash := HashPassword(password)
	if hash != user.hashedPassword {
		return Session{}, errors.New("Invalid email or password")
	}
	newId, err := GenerateUuid()
	if err != nil {
		return Session{}, err
	}
	newId = email + ":" + newId
	expires := time.Now().Add(8 * time.Hour)

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	s, ok := sessions[email]
	if !ok {
		s.Id = newId
	}
	s.Expires = expires
	sessions[email] = s
	return s, nil
}
