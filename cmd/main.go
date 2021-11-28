package main

import (
	"embed"
	"log"
	"net/http"
	"os"

	adm "auth/internal/adm"
	auth "auth/internal/auth"
	_ "auth/internal/db"
)

//go:embed web
var index embed.FS

func main() {
	//envs inicio server
	PORT := os.Getenv("DEVPORT")
	ADDR := os.Getenv("DEVADDRESS")

	log.Print("Server Running on port: " + ADDR + ":" + PORT)
	huser := http.HandlerFunc(auth.UserFunc)
	hadmin := http.HandlerFunc(adm.UserFunc)
	hrootServe := http.HandlerFunc(rootServe)

	http.Handle("/user/", auth.CORS(auth.ValidateToken(huser)))
	http.Handle("/adm/", auth.CORS(auth.ValidateToken(auth.ValidateAdmin(hadmin))))
	http.Handle("/", auth.CORS(hrootServe))
	http.HandleFunc("/health", health)
	log.Fatal(http.ListenAndServe(ADDR+":"+PORT, nil))
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

func health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
