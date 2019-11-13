package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleGet(t *testing.T) {
	//Creates multiplexer to run teset on
	mux := http.NewServeMux()

	//attaches handler you want to test
	mux.HandleFunc("/post/", handleRequest)

	//Captures returned HTTP response
	writer := httptest.NewRecorder()

	//Creates request to handler you want to test
	request, _ := http.NewRequest("GET", "/post/1", nil)

	//Sends request to tested handler
	mux.ServeHTTP(writer, request)

	//Checks Responserecorder for results
	if writer.Code != 200 {
		t.Errorf("Response code is %v", writer.Code)
	}

	var post Post

	json.Unmarshal(writer.Body.Bytes(), &post)
	if post.Id != 1 {
		t.Error("Cannot retrieve JSON post")
	}
}

func TestHandlePut(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/post/", handleRequest)
	writer := httptest.NewRecorder()
	json := strings.NewReader(`{"content":"Updated post","author":"Sau Sheong"}`)
	request, _ := http.NewRequest("PUT", "/post/1", json)
	mux.ServeHTTP(writer, request)
	if writer.Code != 200 {
		t.Errorf("Response code is %v", writer.Code)
	}
}
