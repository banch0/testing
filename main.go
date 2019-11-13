package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		st := "hello world!"
		// w.Write([]byte(st)) // variant 1
		fmt.Fprintf(w, st) // variant 2
	})

	http.ListenAndServe(":8888", nil)
}
