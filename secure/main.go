package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"text/template"

	"io/ioutil"
	"net/http"
	"os"
)

// TodoPageData ..
type TodoPageData struct {
	PageTitle string
	Todos     []Todo
}

// Todo ...
type Todo struct {
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

// ToString ...
func (t Todo) ToString() string {
	bytes, _ := json.Marshal(t)
	return string(bytes)
}

func getTodos() []Todo {
	todos := make([]Todo, 3)
	raw, _ := ioutil.ReadFile("./todo.json")
	json.Unmarshal(raw, &todos)
	return todos
}

// RouteFirst ...
type RouteFirst struct{}

// ServeHTTP ...
func (r RouteFirst) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(res, "New RouteFirst")
}

func getStartTempl(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(res, "Digida digida digida")
}

// Logger ...
func Logger(h http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		name := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
		fmt.Println("Handler function called - " + name)
		h(res, req)
	}
}

func chen(res http.ResponseWriter, req *http.Request) {
	tmpl := `<html><head><title>Go Web Programming</title></head>
	<body>
	<h1>Headline2</h1>
	<p>{{.}}</p>
	</body>`
	t := template.New("tmpl2.html")
	t, _ = t.Parse(tmpl)
	t.Execute(res, "Hello World232!")
}

func index(w http.ResponseWriter, r *http.Request) {
	t, ok := template.ParseFiles("temaplate/index.html")
	if ok != nil {
		fmt.Println("ok")
	}
	t.Execute(w, "Hello Wolrd!")
}

func main() {
	firstRoute := RouteFirst{}
	log.Println(os.Getenv("PORT"))

	// temp, _ := template.Must(template.Parse("template/index.html"))
	// // tmp := template.New("template/index.html")

	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	data := TodoPageData{
	// 		PageTitle: "My todos",
	// 		Todos:     getTodos(),
	// 	}
	// 	tmp.Execute(w, data)
	// })
	http.HandleFunc("/chen", chen)
	http.HandleFunc("/ind", index)
	http.Handle("/main", &firstRoute)
	http.HandleFunc("/", Logger(getStartTempl))
	os.Setenv("PORT", "8888")
	http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}
