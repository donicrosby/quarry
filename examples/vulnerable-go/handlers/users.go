package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

var userStore = map[string]User{
	"1": {ID: "1", Name: "Alice Admin", Email: "alice@example.com", Role: "admin"},
	"2": {ID: "2", Name: "Bob User", Email: "bob@example.com", Role: "user"},
	"3": {ID: "3", Name: "Carol User", Email: "carol@example.com", Role: "user"},
}

// ListUsers returns all users.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	users := make([]User, 0, len(userStore))
	for _, u := range userStore {
		users = append(users, u)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GetUser returns a user record identified by the last path segment.
// No authorization check is performed — any caller may read any record.
func GetUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/users/")
	if id == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	user, ok := userStore[id]
	if !ok {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
