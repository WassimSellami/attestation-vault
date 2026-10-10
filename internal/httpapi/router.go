package httpapi

import (
	"net/http"
)

func NewRouter(h *Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /api/v1/attest/challenge", h.Challenge)
	mux.HandleFunc("POST /api/v1/attest/release", h.Release)
	return mux
}
