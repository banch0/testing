package main

import (
	"html/template"
	"net/http"
)

func process(w http.ResponseWriter, r *http.Request) {
	var t *template.Template
	t, _ = template.ParseFiles("index.html", "content.html")
	t.ExecuteTemplate(w, "index", "")
}

func index(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("index.html")
	// content := `I asked: <i>"What's up?"</i>`
	t.Execute(w, nil)
}

func main() {
	server := http.Server{
		Addr: ":8080",
	}

	http.HandleFunc("/process", process)
	http.HandleFunc("/", index)
	server.ListenAndServe()
}
