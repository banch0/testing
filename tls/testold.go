package main

import (
	"fmt"
	"net/http"
	"reflect"
	"runtime"

	"golang.org/x/net/http2"
)

type MyHandler struct{}

func (h *MyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!!!")
}

type HelloHandler struct{}

func (h *HelloHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello!")
}

type WorldHandler struct{}

func (h *WorldHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "World!")
}

func worlds(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Just some words!") // server := http.Server{
	// 	Addr: "8080",
	// }
}

func log(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
		fmt.Println("Handler function called - " + name)
		h(w, r)
	}
}

// func log(h http.Handler) http.Handler {
// 	return http.HandlerFunc (func(w http.ResponseWriter, r *http.Request) {
// 	fmt.Printf("Handler called - %T\n", h)
// 	h.ServeHTTP (w, r)
// 	})
//    }

func main() {
	handler := MyHandler{}

	// server := http.Server{
	// 	Addr: ":8080",
	// 	Handler: &handler,
	// }

	hello := HelloHandler{}
	world := WorldHandler{}

	server := http.Server{
		Addr: ":8080",
	}

	http.HandleFunc("/word/", log(worlds))
	http.Handle("/hello", &hello)
	http.Handle("/world", &world)
	http.Handle("/", &handler)

	http2.ConfigureServer(&server, &http2.Server{})
	server.ListenAndServeTLS("cert.pem", "key.pem")

	//server.ListenAndServe()
}
