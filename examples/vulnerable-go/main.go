package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/quarry-research/vulnerable-go/handlers"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("GET /users/", handlers.GetUser)
	mux.HandleFunc("GET /users", handlers.ListUsers)
	mux.HandleFunc("POST /admin/exec", handlers.RunCommand)

	fmt.Fprintf(os.Stderr, "listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
