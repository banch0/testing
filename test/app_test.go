package main

import (
	"testing"
	"time"
)

//works for 1 second
func TestParallel_1(t *testing.T) {
	//calls Parallel function to run test cases in parallel
	t.Parallel()
	time.Sleep(1 * time.Second)
}

//works for 2 seconds
func TestParallel_2(t *testing.T) {
	t.Parallel()
	time.Sleep(2 * time.Second)
}

//works for 3 seconds
func TestParallel_3(t *testing.T) {
	t.Parallel()
	time.Sleep(3 * time.Second)
}

func TestLongRunningTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}
	time.Sleep(10 * time.Second)
}

func TestDecode(t *testing.T) {
	post, err := decode("post.json")
	if err != nil {
		t.Error(err)
	}

	if post.Id != 1 {
		t.Error("Wrong id, was expecting 1 but got", post.Id)
	}

	if post.Content != "Hello World!" {
		t.Error("Wrong content, was expecting 'Hello World!' but got",
			post.Content)
	}
}

func TestEncode(t *testing.T) {
	t.Skip("Skipping encoding for now")
}

//go test -v -cover
//flag parallel indicates maximum test case in parallel
//go test -v -short -parallel 3
