package main

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

var (
	mu           sync.Mutex
	held         [][]byte
	gcRequests   atomic.Int64
	heapRequests atomic.Int64
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/heap", func(w http.ResponseWriter, r *http.Request) {
		heapRequests.Add(1)
		if r.URL.Query().Get("gc") == "1" {
			gcRequests.Add(1)
		}
		pprof.Handler("heap").ServeHTTP(w, r)
	})
	mux.HandleFunc("/gc-count", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, gcRequests.Load())
	})
	mux.HandleFunc("/heap-count", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, heapRequests.Load())
	})
	mux.HandleFunc("/gc", func(w http.ResponseWriter, _ *http.Request) {
		runtime.GC()
		fmt.Fprintln(w, "collected")
	})
	mux.HandleFunc("/grow", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		chunk := make([]byte, 4<<20)
		for i := 0; i < len(chunk); i += 4096 {
			chunk[i] = 1
		}
		held = append(held, chunk)
		fmt.Fprintf(w, "%d\n", len(held))
	})
	mux.HandleFunc("/clear", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		held = nil
		mu.Unlock()
		runtime.GC()
		fmt.Fprintln(w, "cleared")
	})
	address := os.Getenv("GOMEMTOP_TEST_ADDR")
	if address == "" {
		address = "127.0.0.1:6069"
	}
	if err := http.ListenAndServe(address, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
