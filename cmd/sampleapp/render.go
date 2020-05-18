package main

import (
	"html/template"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/userinfo"
)

var (
	indexTemplate    = template.Must(template.ParseFiles("../../web/template/index.html"))
	callbackTemplate = template.Must(template.ParseFiles("../../web/template/callback.html"))
	errorTemplate    = template.Must(template.ParseFiles("../../web/template/error.html"))
)

func renderIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	indexTemplate.Execute(w, nil)
}

func renderCallback(w http.ResponseWriter, userInfoResponse userinfo.Response) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	callbackTemplate.Execute(w, userInfoResponse)
}

func renderUnauthorizedError(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusUnauthorized)
	errorTemplate.Execute(w, "authroization code is invalid, expired or revoked. please try again.")
}

func renderUnexpectedError(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusInternalServerError)
	errorTemplate.Execute(w, "unexpected error, so try again")
}
