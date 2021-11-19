package main

import (
	"log"
	"net/http"

	adm "github.com/maximotejeda/auth/internal/adm"
	auth "github.com/maximotejeda/auth/internal/auth"
	_ "github.com/maximotejeda/auth/internal/db"
)

func main() {
	PORT := "0.0.0.0:8080"
	log.Print("Server Running on port: " + PORT)
	huser := http.HandlerFunc(auth.UserFunc)
	http.Handle("/user/", auth.ValidateToken(huser))
	http.HandleFunc("/adm/", adm.UserFunc)
	http.HandleFunc("/", rootServe)
	log.Fatal(http.ListenAndServe(PORT, nil))
}

func rootServe(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL)
	p := "." + r.URL.Path
	if p != "./" {
		w.Write([]byte("not found"))
		return
	}
	p = "web/index.html"
	http.ServeFile(w, r, p)

}
