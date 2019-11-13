package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	// "golang.org/x/net/http2"
	// "github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

func setMessage(w http.ResponseWriter, r *http.Request) {
	msg := []byte("Hello World!")
	c := http.Cookie{
		Name:  "flash",
		Value: base64.URLEncoding.EncodeToString(msg),
	}
	http.SetCookie(w, &c)
}

func showMessage(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("flash")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprintln(w, "No message found")
		}
	} else {
		rc := http.Cookie{
			Name:    "flash",
			MaxAge:  -1,
			Expires: time.Unix(1, 0),
		}
		http.SetCookie(w, &rc)
		val, _ := base64.URLEncoding.DecodeString(c.Value)
		fmt.Fprintln(w, string(val))
	}
}

type Post struct {
	User    string
	Threads []string
}

// func hello(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
// 	fmt.Println(p)
//  	fmt.Fprintf(w, "hello, %s!\n", p.ByName("name"))
// }

func setCookie(w http.ResponseWriter, r *http.Request) {
	c1 := http.Cookie{
		Name:     "first_cookie",
		Value:    "Go Web Programming-1",
		HttpOnly: true,
	}
	c2 := http.Cookie{
		Name:     "second_cookie",
		Value:    "Manning Publications Corp",
		HttpOnly: true,
	}
	// w.Header().Set("Set-Cookie", c1.String())
	// w.Header().Add("Set-Cookie", c2.String())
	http.SetCookie(w, &c1)
	http.SetCookie(w, &c2)
}

func getCookie(w http.ResponseWriter, r *http.Request) {
	// h := r.Header["Cookie"]
	// fmt.Fprintln(w, h)
	c1, err := r.Cookie("first_cookie")
	if err != nil {
		fmt.Fprintln(w, "Cannot get the first cookie")
	}
	cs := r.Cookies()
	fmt.Fprintln(w, c1)
	fmt.Fprintln(w, cs)
}

func writeExample(w http.ResponseWriter, r *http.Request) {
	str := `<html>
   <head><title>Go Web Programming</title></head>
   <body><h1>Hello World</h1></body>
   </html>`
	w.Write([]byte(str))
}

func writeHeaderExample(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(501)
	fmt.Fprintln(w, "No such service, try next door")
}

func headerExample(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "http://google.com")
	w.WriteHeader(302)
}

func jsonExample(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	post := &Post{
		User:    "Sau Sheong",
		Threads: []string{"first", "second", "third"},
	}
	json, _ := json.Marshal(post)
	w.Write(json)
}

func process(w http.ResponseWriter, r *http.Request) {
	// r.ParseForm()
	r.ParseMultipartForm(1024)
	// fmt.Fprintln(w, r.Form)
	fileHeader := r.MultipartForm.File["uploaded"][0]
	file, err := fileHeader.Open()
	if err == nil {
		data, err := ioutil.ReadAll(file)
		if err == nil {
			fmt.Fprintln(w, string(data))
		}
	}
}

func headers(w http.ResponseWriter, r *http.Request) {
	h := r.Header
	fmt.Fprintln(w, h)
}

func body(w http.ResponseWriter, r *http.Request) {
	len := r.ContentLength
	body := make([]byte, len)
	r.Body.Read(body)
	fmt.Fprintln(w, string(body))
}

func main() {
	// mux := httprouter.New()
	// mux.GET("/hello/:name", hello)
	server := http.Server{
		Addr: ":8080",
		//Handler: mux,
	}

	// http2.ConfigureServer(&server, &http2.Server{})
	// server.ListenAndServeTLS("cert.pem", "key.pem")
	http.HandleFunc("/body", body)
	http.HandleFunc("/headers", headers)
	http.HandleFunc("/process", process)
	http.HandleFunc("/write", writeExample)
	http.HandleFunc("/writeheader", writeHeaderExample)
	http.HandleFunc("/json", jsonExample)
	http.HandleFunc("/redirect", headerExample)
	http.HandleFunc("/set_cookie", setCookie)
	http.HandleFunc("/get_cookie", getCookie)
	http.HandleFunc("/set_message", setMessage)
	http.HandleFunc("/show_message", showMessage)
	server.ListenAndServe()
	// curl -I --http2 --insecure https://localhost:8080/hello/bob
}
