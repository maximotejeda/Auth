package auth

import (
	"database/sql"
	"encoding/json"

	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/maximotejeda/auth/internal/db"
)

var database *sql.DB
var dbFile string = "user.db"
var dbDir string = "db"

// Main entrypoint to handle response
func UserFunc(w http.ResponseWriter, r *http.Request) {
	database, _ = sql.Open("sqlite3", dbDir+"/"+dbFile+"?mode=memory&cache=shared")
	defer database.Close()
	uriResPath := r.URL.Path[len("/adm/"):]
	uriResPath = strings.Split(uriResPath, "/")[0]
	defer log.Print(r.URL.Path, " - ", uriResPath, " - ", r.Method)

	switch r.Method {
	case "GET":
		switch uriResPath {
		case "users":
			getUsers(database, w, r)
		case "user":
			getUser(database, w, r)
		}

	case "POST":
		switch uriResPath {
		case "logout":
			w.Write([]byte("You logout."))
		case "register":
			addUser(database, w, r)
		default:
			http.Error(w, "Recurso solicitado no Disponible", 404)
		}

	case "PUT":
		editUser(database, w, r)

	case "DELETE":
		deleteUser(database, w, r)
	default:
		w.Header().Set("Allow", http.MethodPost+" "+http.MethodGet)
		http.Error(w, "Method not Allowed", 400)

	}
}

// Set response to aplication/json
func setJson(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "aplication/json")
}

func getUsers(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	user := db.User{}
	lista := user.GetAll(data)
	setJson(&w)
	json.NewEncoder(w).Encode(lista)
}

// get a single user with the parameters on the body
// Queremos que sea REST compliant asi que aceptaremos busqueda de usuario por parametros en la URL
func getUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Path[len("/adm/user/"):]

	user := db.User{UserName: username}

	user.Query(data)
	if user.Id == 0 {
		http.Error(w, "Usuario no encontrado", 404)
		return
	}

	log.Print(user.String())
	setJson(&w)
	json.NewEncoder(w).Encode(user)
}

// Add a user to the database
// si es  correcta la inclusion del usuario devuelve los datos recien introducidos
func addUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	type Password struct {
		Password string
	}

	if err != nil {
		http.Error(w, "Something went wrong with the Request.", 400)
		//w.Write([]byte("Not Posible to read body"))
		return
	}
	defer r.Body.Close()
	//w.Write(body)
	passwd := Password{}
	user := db.User{}
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print(err)
		http.Error(w, "Hay un problema con el json y la informacion de usuario.", 400)
		return
	}
	if err := json.Unmarshal(body, &passwd); err != nil {
		log.Print(err)
		http.Error(w, "Hay un problema con el json y el password.", 400)
		return
	}
	if user.IsEmpty() {
		http.Error(w, "Request Body must contains an user name To create new user.", 400)
		log.Print("ERROR! No user name when trying to add an user to database.")
		return
	}
	if user.Exist(data) {
		http.Error(w, "Username Alredy existed", 409)
		return
	}

	if passwd.Password == "" {
		log.Print("ERROR! Password required to add user Request Aborted.", passwd)
		http.Error(w, "Password Required", 400)
		return
	}
	user.PasswordHash(passwd.Password)
	user.Rol = "viewer"

	id, rows := user.Add(data)
	log.Print("ID: ", id, " -- Columnas: ", rows)
	user.Query(data)
	setJson(&w)
	json.NewEncoder(w).Encode(user)
	//	w.Write([]byte("success"))

}

// Edit parameters from a user in the database
// Solo los parametros Nombre apellido correo y role son actualizables
// Funcion protegida por middleware solo admin o usuario puede actualizar
// El password Se manejara en otra funcion
// Se necesita ID Username para actualizar esta funcion correctamente
func editUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte("Incorrect Body."))
		return
	}
	defer r.Body.Close()

	user := db.User{}
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print(err)
		http.Error(w, "Hay un problema con el json.", 404)
		return
	}

	if user.IsEmpty() {
		http.Error(w, "Request Body must contains an username or id To delete a resource.", 404)
		log.Print("ERROR! No user name when trying to delete an user from database.")
		return
	}
	if !user.Exist(data) {
		http.Error(w, "user not in database.", 404)
		return
	}

	lastuser := db.User{Id: user.Id, UserName: user.UserName}
	lastuser.Query(data)

	if user.Name != "" && user.Name != lastuser.Name {
		lastuser.Name = user.Name
	}
	if user.LastName != "" && user.LastName != lastuser.LastName {
		lastuser.LastName = user.LastName
	}
	if user.Email != "" && user.Email != lastuser.Email {
		lastuser.Email = user.Email
	}
	if user.Rol != "" && user.Rol != lastuser.Rol {
		lastuser.Rol = user.Rol
	}
	if user.Active != 0 && user.Active != lastuser.Active {
		lastuser.Active = user.Active
	}

	lastuser.Update(data)
	setJson(&w)
	json.NewEncoder(w).Encode(lastuser)
}

// Delete a user From the database
// El json de acceso debe proveer id o username para funcionar
// Estara protegida por un middleware que verificara el token de acceso
func deleteUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte("Incorrect Body."))
		return
	}
	defer r.Body.Close()
	user := db.User{}
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print(err)
		http.Error(w, "Hay un problema con el json.", 404)
		return
	}
	if user.IsEmpty() {
		http.Error(w, "Request Body must contains an username or id To delete a resource.", 404)
		log.Print("ERROR! No user name when trying to delete an user from database.")
		return
	}
	if user.Exist(data) {
		http.Error(w, "user not in database.", 404)
		return
	}
	user.Query(data)
	user.Delete(data)
	w.Write([]byte("Usuario eliminado\n" + user.String()))
}
