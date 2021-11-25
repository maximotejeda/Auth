package main

import (
	"embed"

	"log"
	"net/http"

	adm "auth/internal/adm"
	auth "auth/internal/auth"
	_ "auth/internal/db"
)

//go:embed web
var index embed.FS

func main() {
	PORT := "0.0.0.0:8000"
	log.Print("Server Running on port: " + PORT)
	huser := http.HandlerFunc(auth.UserFunc)
	hadmin := http.HandlerFunc(adm.UserFunc)
	hrootServe := http.HandlerFunc(rootServe)
	http.Handle("/user/", auth.CORS(auth.ValidateToken(huser)))
	http.Handle("/adm/", auth.CORS(auth.ValidateToken(auth.ValidateAdmin(hadmin))))
	http.Handle("/", auth.CORS(hrootServe))
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
	//http.ServeFile(w, r, p)
	//http.FileServer(http.FS(index))
	file, _ := index.ReadFile("web/index.html")
	w.Write(file)
}
