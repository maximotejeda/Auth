package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"auth/internal/db"
	"auth/internal/emailer"
)

var database *sql.DB
var dbFile string = os.Getenv("DEVDBNAME")
var dbDir string = os.Getenv("DEVDBDIR")

type responseForm struct {
	Status  int16  `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// Main entrypoint to handle response
func UserFunc(w http.ResponseWriter, r *http.Request) {
	database, _ = sql.Open("sqlite3", dbDir+"/"+dbFile+"?mode=memory&cache=shared")
	defer database.Close()
	uriResPath := r.URL.Path[len("/user/"):]
	uriResPath = strings.Split(uriResPath, "/")[0]
	defer log.Print(r.URL.Path, " - ", uriResPath, " - ", r.Method)

	switch r.Method {
	case "GET":
		getUser(database, w, r)
	case "POST":
		switch uriResPath {
		case "logout":
			w.Write([]byte("You logout."))
		case "login":
			login(database, w, r)
		case "register":
			addUser(database, w, r)
		case "accountrecovery":
			recoverAccount(database, w, r)
		case "chpwd":
			changePassword(database, w, r)
		default:
			http.Error(w, "Recurso solicitado no Disponible", 404)
		}

	case "PUT":
		editUser(database, w, r)

	case "DELETE":
		deleteUser(database, w, r)
	default:
		w.Header().Set("Allow", http.MethodPost+" "+http.MethodGet)
		http.Error(w, "Method not Allowed", http.StatusMethodNotAllowed)

	}
}

// Set response to aplication/json
func setJson(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "aplication/json")
}

// get a single user with the parameters on the body
// Queremos que sea REST compliant asi que aceptaremos busqueda de usuario por parametros en la URL
func getUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	//id := r.URL.Path[len("/user/"):]
	auth := r.Header.Get("claims")
	if auth == "" {
		http.Error(w, "Authorization is required!", http.StatusUnauthorized)
		return
	}
	//	log.Print("Calling get authenticated ", auth)

	user := db.User{}
	err := json.Unmarshal([]byte(auth), &user)
	if err != nil {
		log.Print("Auth: getUser: unmarshaling: ", err)
	}

	user.Query(data)

	setJson(&w)
	json.NewEncoder(w).Encode(user)
}

// Add a user to the database
// si es  correcta la inclusion del usuario devuelve los datos recien introducidos
func addUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	type Password struct {
		Password string
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Something went wrong with the Request.", 400)
		return
	}

	defer r.Body.Close()

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
		http.Error(w, "Username Alredy existed", http.StatusConflict)
		return
	}

	if passwd.Password == "" {
		log.Print("ERROR! Password required to add user Request Aborted.", passwd)
		http.Error(w, "Password Required.", 400)
		return
	}
	user.PasswordHash(passwd.Password)
	user.Rol = "viewer"

	id, rows := user.Add(data)
	log.Print("ID: ", id, " -- Columnas: ", rows)
	user.Query(data)

	setJson(&w)
	json.NewEncoder(w).Encode(user)
}

// Edit parameters from a user in the database
// Solo los parametros Nombre apellido correo y role son actualizables
// Funcion protegida por middleware solo admin o usuario puede actualizar
// El password Se manejara en otra funcion
// Se necesita ID Username para actualizar esta funcion correctamente
func editUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("claims")
	if auth == "" {
		http.Error(w, "You must be logged in to access", http.StatusUnauthorized)
		return
	}

	logedUser := db.User{}
	err := json.Unmarshal([]byte(auth), &logedUser)
	if err != nil {
		log.Print("Auth: editUser: unmarcharl logedUser", err)
	}
	logedUser.Query(data)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Wrong request Parameters", 400)
		log.Print("Auth: editUser: ioReadall: ", err)
		return
	}
	defer r.Body.Close()

	user := db.User{}
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print("Auth: editUser: unmarshal user: ", err)
		http.Error(w, "Wrong Request Parameters!", 400)
		return
	}

	if user.IsEmpty() {
		http.Error(w, "Resource not Found!", 400)
		log.Print("Auth: editUser: ERROR! No user name when trying to delete an user from database.")
		return
	}
	if !user.Exist(data) {
		http.Error(w, "Resource Not Found!.", 404)
		log.Print("Auth: EditUser: user not in database", user.String())
		return
	}

	lastuser := db.User{Id: user.Id, UserName: user.UserName}
	lastuser.Query(data)
	if logedUser.UserName != user.UserName {
		http.Error(w, "You can edit only your own data.", http.StatusForbidden)
		return
	}
	if user.Name != "" && user.Name != lastuser.Name {
		lastuser.Name = user.Name
	}
	if user.LastName != "" && user.LastName != lastuser.LastName {
		lastuser.LastName = user.LastName
	}
	if user.Email != "" && user.Email != lastuser.Email {
		lastuser.Email = user.Email
	}

	lastuser.Update(data)
	setJson(&w)
	json.NewEncoder(w).Encode(lastuser)

}

// Delete a user From the database
// El json de acceso debe proveer id o username para funcionar
// Estara protegida por un middleware que verificara el token de acceso
func deleteUser(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	// start comprobacion
	auth := r.Header.Get("claims")
	if auth == "" {
		http.Error(w, "You must be logged in to access", http.StatusUnauthorized)
		return
	}
	log.Print("Calling edit authenticated ", auth)

	logedUser := db.User{}
	err := json.Unmarshal([]byte(auth), &logedUser)
	if err != nil {
		log.Print("Auth: deleteUser: unmarshal: ", err)
	}
	// Aqui auth Ends
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Content of body is incorrect", 400)
		return
	}
	defer r.Body.Close()
	user := db.User{}
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print("Auth: deleteUser: unmarshal2: ", err)
		http.Error(w, "Content of body is incorrect", 400)
		return
	}
	if user.IsEmpty() {
		http.Error(w, "Wrong Request Content", 404)
		log.Print("Auth: deleteUser: empty user: ERROR! No user name when trying to delete an user from database.")
		return
	}
	if !user.Exist(data) {
		http.Error(w, "User not found!.", 404)
		return
	}

	user.Query(data)
	if user.UserName != logedUser.UserName {
		http.Error(w, "Permision denied.", http.StatusForbidden)
		return
	}
	user.Delete(data)
	json.NewEncoder(w).Encode(user)

}

// Funcion de login en el servicio
// Funcion expuesta
func login(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	log.Print("Request: \n", r.RemoteAddr, "\n", r.Host)
	type respo struct {
		db.User
		Token string `json:"token"`
	}
	type password struct {
		Password string
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Print("Auth: login: readBody: ", err)
	}

	passwd := password{}
	user := db.User{}

	if err := json.Unmarshal(body, &user); err != nil {
		log.Print("login:user marshal: ", err)
		http.Error(w, "Request parameters error.", 400)
	}
	if err := json.Unmarshal(body, &passwd); err != nil {
		log.Print("login: password marsharl", err)
		http.Error(w, "Request parameters error.", 400)
	}
	// Comprobamos si existe el usuario

	if !user.Exist(data) {
		http.Error(w, "Bad Credentials: Incorrect user or password.", http.StatusUnauthorized)
		log.Print("Auth: login: Intentando login a Usuario que no existe")
		return
	}

	if result := user.ComparePasswd(passwd.Password, data); !result {
		log.Print("Auth: compare Password: worng", user.String())
		http.Error(w, "Bad Credentials: Incorrect user or password.", http.StatusUnauthorized)
		return
	}
	logTime := os.Getenv("DEVLOGINDURATION")
	user.Query(data)
	r.Header.Set("TimeRequested", logTime)
	r.Header.Set("Task", "login")
	token := createToken(&user, r)
	resp := respo{
		User:  user,
		Token: token,
	}
	setJson(&w)
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
	json.NewEncoder(w).Encode(resp)
}

func recoverAccount(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	// Caracteristicas del mail que queremos enviar
	// env
	devmail := os.Getenv("DEVSMTPEMAIL")
	mail := emailer.Emailer{
		Copys:   []string{devmail},
		Subject: "Recovery Account Email.",
		Content: "",
	}

	origin := r.Header.Get("Origin")
	origin = strings.Replace(origin, "api.", "", 1)
	log.Print(origin)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Print("Auth: login: readBody: ", err)
	}
	user := db.User{}
	//envian username por body
	if err := json.Unmarshal(body, &user); err != nil {
		log.Print("recovery: unmarshal: ", err)
	}
	if !user.Exist(data) {
		time.Sleep(time.Second * 1)
		w.Write([]byte("Request procesada en breve reciviras un Email."))
		log.Print("Auth: login: Intentando login a Usuario que no existe")
		return
	}
	user.Query(data)
	mail.Emails = append(mail.Emails, user.Email)
	r.Header.Set("TimeRequested", "10")
	r.Header.Set("Task", "chpwd")
	token := createToken(&user, r)

	resp := responseForm{
		Status:  int16(200),
		Message: "Shortly you'll recive an email with instructions on how to change your password",
		Token:   token,
	}
	initbody := `
<html>
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
   <title>Password Change</title>
</head>
<body>
<h1>Password Recovery Operation</h1>
<h2>Steps to reset your Password:</h2>
<p>If you wish to change your password click in the following link: </p>
<p>
`
	endbody := `</p>
<p>If you did not initiate a password change operation, please ignore this email.</p>
</body>
</html>
`

	mail.Content = initbody + origin + "/chpwd?token=" + token + endbody
	defer emailer.SendMail(mail)
	json.NewEncoder(w).Encode(resp)

}

func changePassword(data *sql.DB, w http.ResponseWriter, r *http.Request) {
	// start comprobacion
	auth := r.Header.Get("claims")
	if auth == "" {
		http.Error(w, "You must be logged in to access", http.StatusUnauthorized)
		return
	}
	log.Print("Calling edit authenticated ", auth)

	logedUser := db.User{}
	err := json.Unmarshal([]byte(auth), &logedUser)
	if err != nil {
		log.Print("Auth: deleteUser: unmarshal: ", err)
	}
	// Aqui auth Ends

	// primero obtenemos la path
	res := r.URL.Query()
	user := db.User{}
	//log.Print(r.Header)
	token := res.Get("token")

	claims, err := ExternalValidator(token)
	if err != nil {
		log.Print("Error validador externo: ", err)
	}
	err = json.Unmarshal(claims, &user)
	if err != nil {
		log.Print("Change pwd: unmarshal claims: ", err)
	}
	//log.Print(string(claims))

}
