package db

import (
	st "auth/internal/structure"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var database *sql.DB
var (
	dbFile = os.Getenv("DEVDBNAME")
	dbDir  = os.Getenv("DEVDBDIR")
)

type User struct {
	Id       int    `json:"id"`
	UserName string `json:"username"`
	Name     string `json:"name"`
	LastName string `json:"lastname"`
	password string `json:"-"`
	Email    string `json:"email"`
	Rol      string `json:"rol"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
	Active   int    `json:"active"`
}

// On import from other package init function is executed first
func init() {
	// Creamos la estructura de directorio archivo deseado en este caso "dir /db", "archivo user.db"
	st.CreaDual(dbDir, dbFile)
	var err error
	// carga el archivo de la db en memoria
	database, err = sql.Open("sqlite3", dbDir+"/"+dbFile+"?mode=memory&cache=shared")
	if err != nil {
		fmt.Println(err)
	}
	defer database.Close()

	defer addAdmin(database)
	defer TableCreate()

	log.Print("Conectado a db.")

}

// test if theres a table in the db
func TableCreate() {
	creaTabla := `CREATE TABLE IF NOT EXISTS 'user'(
	id integer primary key autoincrement,
	username varchar(100),
	name varchar(100),
	lastname varchar(100),
        email varchar(150),
	password varchar(1000),
        rol varchar(150),
        created varchar(100),
        updated varchar(100),
        active  integer);
        `
	crea, err := database.Prepare(creaTabla)
	if err != nil {
		fmt.Errorf("%s", err)
	}
	crea.Exec()
	log.Print("Tabla user creada.")
}

func addAdmin(data *sql.DB) {

	user := User{
		UserName: "maximo",
		Name:     "Maximo",
		LastName: "tejeda",
		Email:    "maximotejeda@gmail.com",
		Rol:      "admin",
		Active:   1,
	}
	if user.Exist(data) {
		log.Print("USER Admin! alredy in database.")
		return
	}
	user.PasswordHash("prueba")
	log.Print("Creando Usuario Administrador.")
	user.Add(database)
}

func (u *User) String() string {
	return fmt.Sprintf("Username:\t%s\nName:\t%s\nLastName:\t%s\nEmail:\t%s\nRole:\t%s\nCreated:\t%s\nUpdated:\t%s\nActive:\t%d\n", u.UserName, u.Name, u.LastName, u.Email, u.Rol, u.Created, u.Updated, u.Active)
}

//Funcion para determinar si la estructura esta vacia
func (u *User) IsEmpty() bool {
	if u.Id == 0 && u.UserName == "" {
		return true
	}
	return false
}

// Funcion para comprobar que existe ese usename
func (u *User) Exist(data *sql.DB) bool {
	var username string
	query := "select username from user where username = ?"
	err := data.QueryRow(query, strings.ToLower(u.UserName)).Scan(&username)

	if err != nil && errors.Is(err, sql.ErrNoRows) {
		// Si el usuario pasado en el json no esta en la base de datos insertalo
		return false
	}
	log.Print("Usuario Existente ", u.UserName)
	return true
}

func (u *User) ByName(name string, data *sql.DB) {
	query := "select * from user where name = ?"
	err := data.QueryRow(query, name).Scan(&u.Id, &u.UserName, &u.Name, &u.LastName, &u.Email, &u.password, &u.Rol)
	if err != nil {
		log.Print(err)
		return
	}

}

func (u *User) ByUserName(userName string, data *sql.DB) {
	query := "select id, username, name, lastname, email, rol, active, created, updated from user where username = ?"
	err := data.QueryRow(query, userName).Scan(&u.Id, &u.UserName, &u.Name, &u.LastName, &u.Email, &u.Rol, &u.Active, &u.Created, &u.Updated)
	log.Println(userName)
	if err != nil {
		log.Print(err)
		return
	}

}
func (u *User) ByID(id string, data *sql.DB) {
	query := "select id, username, name, lastname, email, rol, active, created, updated from user where id = ?"
	err := data.QueryRow(query, id).Scan(&u.Id, &u.UserName, &u.Name, &u.LastName, &u.Email, &u.Rol, &u.Active, &u.Created, &u.Updated)
	if err != nil {
		log.Print(err)
		return
	}
}

func (u *User) ByLastName(last string, data *sql.DB) []User {
	getUser := "select * from user where lastname='" + last + "'"
	var usersList []User
	log.Println(getUser)
	rows, err := data.Query(getUser)
	if err != nil {
		fmt.Errorf("error raro aqui %s", err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&u.Id, &u.UserName, &u.Name, &u.LastName, &u.Email, &u.password, &u.Rol)
		usersList = append(usersList, *u)
		if err != nil {
			fmt.Println(err)
		}

	}
	err = rows.Err()
	if err != nil {
		log.Print("Aqui en rows pasa algo")
		log.Fatal(err)
	}
	return usersList
}

//Get All data in the table.
func (u *User) GetAll(data *sql.DB) []User {
	getUser := "select id, username, name, lastname, email, rol, active, created, updated from user"
	QgetUsers, err := data.Prepare(getUser)
	if err != nil {
		fmt.Errorf("error raro aqui %s", err)
	}
	var usersList []User

	rows, err := QgetUsers.Query()
	//rows, err := data.Query(getUser)
	if err != nil {
		fmt.Errorf("error raro aqui %s", err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&u.Id, &u.UserName, &u.Name, &u.LastName, &u.Email, &u.Rol, &u.Active, &u.Created, &u.Updated)
		usersList = append(usersList, *u)
		if err != nil {
			fmt.Println(err)
		}
	}
	err = rows.Err()
	if err != nil {
		log.Print("rows: Aqui en rows pasa algo: ", err)
	}
	return usersList
}

// query para hacer dinamica la busqueda solo por id y usuario las demas son manuales
func (u *User) Query(data *sql.DB) {
	if u.Id != 0 {
		u.ByID(strconv.Itoa(u.Id), data)
		return
	}
	if u.UserName != "" {
		u.ByUserName(u.UserName, data)
		return
	}

}

// Funcion para introducir los datos de los structs en la base de datos
func (u *User) Add(data *sql.DB) (lastID int64, rowsAffected int64) {
	intro, err := data.Prepare("INSERT INTO user(username, name, lastname, email, password, rol, created, updated, active) VALUES(?,?,?,?,?,?,datetime('now'),datetime('now'),?)")
	if err != nil {
		log.Print(err)
	}
	// Convertimos el nombre se usuario a lower
	u.UserName = strings.ToLower(u.UserName)
	u.Name = strings.ToLower(u.Name)
	u.LastName = strings.ToLower(u.LastName)
	u.Active = 1
	//ejecutamos sentencia sql
	res, err := intro.Exec(u.UserName, u.Name, u.LastName, u.Email, u.password, u.Rol, u.Active)
	if err != nil {
		log.Print(err)
	}
	lastID, err = res.LastInsertId()
	if err != nil {
		log.Print(err)
	}
	rowsAffected, err = res.RowsAffected()
	if err != nil {
		log.Print(err)
	}
	return
}

// Funcion para Actualizar El usuario
func (u *User) Update(data *sql.DB) {
	update, err := data.Prepare("UPDATE user SET name=?, lastname=?, email=?, rol=?, updated=datetime('now') WHERE id=?")
	if err != nil {
		log.Print(err)
	}
	// Ejecutamos la Actualizacion
	_, err = update.Exec(u.Name, u.LastName, u.Email, u.Rol, u.password, u.Id)
	if err != nil {
		log.Print(err)
	}
}

//Actualiza el password de una cuenta solo por id
func (u *User) UpdatePWD(data *sql.DB) {
	update, err := data.Prepare("UPDATE user SET password=?, updated=datetime('now') WHERE id=?")
	if err != nil {
		log.Print(err)
	}
	// Ejecutamos la Actualizacion
	_, err = update.Exec(u.password, u.Id)
	if err != nil {
		log.Print(err)
	}
}

// Funcion para eliminar usuarios de la base de datos
func (u *User) Delete(data *sql.DB) {
	delete, err := data.Prepare("DELETE FROM user WHERE id=?")
	if err != nil {
		log.Print(err)
	}

	//ejecutamos sentencia sql
	_, err = delete.Exec(u.Id)
	if err != nil {
		log.Print(err)
	}

}

// Funcion que Hashea el passwd y lo asigna al pointer
func (u *User) PasswordHash(password string) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	if err != nil {
		log.Print("Error hashing the passwrd", err)
	}
	u.password = string(hashed)
	fmt.Println(u.password)
}

func (u *User) ComparePasswd(password string, data *sql.DB) bool {
	query := "select password from user where id = ? or username = ?"
	err := data.QueryRow(query, u.Id, u.UserName).Scan(&u.password)
	if errors.Is(err, sql.ErrNoRows) {
		log.Print("No results from query. ", err)
		return false
	}
	//log.Print(u.password)
	err = bcrypt.CompareHashAndPassword([]byte(u.password), []byte(password))
	return err == nil
}
