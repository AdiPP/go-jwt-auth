package main

import (
	"log"
	"net/http"
)

func main() {
	// Token
	http.HandleFunc("/tokens", Token)
	http.HandleFunc("/tokens/refresh", RefreshToken)

	// Resource
	http.HandleFunc("/resources", GetResources)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
