package main

import (
	"log"
	"net/http"

	adm "auth/internal/adm"
	auth "auth/internal/auth"
	_ "auth/internal/db"
)

func main() {
	PORT := "0.0.0.0:8080"
	log.Print("Server Running on port: " + PORT)
	huser := http.HandlerFunc(auth.UserFunc)
	hadmin := http.HandlerFunc(adm.UserFunc)
	http.Handle("/user/", auth.ValidateToken(huser))
	http.Handle("/adm/", auth.ValidateToken(auth.ValidateAdmin(hadmin)))
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
