package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func handlerFunc(w http.ResponseWriter, r *http.Request) {
	_, err := fmt.Fprint(w, "<h1>Welcome to my awesome site!</h1>")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return

	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err :=	w.Write([]byte("Hello, World!"))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return

	}
	})

	mux.HandleFunc("/hello", handlerFunc)

	srv := &http.Server{
		Addr:         ":3000",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("Server starting on :3000")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
