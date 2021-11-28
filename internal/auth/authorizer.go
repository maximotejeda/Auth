package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"auth/internal/db"

	"github.com/dgrijalva/jwt-go"
	"github.com/maximotejeda/netrsakeys"
)

type userInfo struct {
	Id         int
	Username   string
	Email      string
	Rol        string
	Host       string
	Remoteaddr string
}

type costumClaims struct {
	*jwt.StandardClaims
	TokeType string
	userInfo
}

var keysDir string = os.Getenv("DEVKEYDIR")

// corre al importar
func init() {
	//env lugar de keys
	netrsakeys.GenerateKeyPair(keysDir)
}

// Creamos un token
func createToken(user *db.User, r *http.Request) string {
	var err error
	// get private key
	file, err := ioutil.ReadFile(keysDir + "privateRSAKey")
	if err != nil {
		log.Print("Error reading Secret key", err)
	}
	signedKey, err := jwt.ParseRSAPrivateKeyFromPEM(file)
	if err != nil {
		log.Print("Error reading Secret key", err)
	}

	verifyBytes, err := ioutil.ReadFile(keysDir + "pubRsaKey.pub")
	if err != nil {
		log.Print("Error reading public key: ", err)
	}

	verifyPubKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Print("Error verifying public key: ", err, verifyPubKey)
		return ""
	}
	var intTime int

	strTime := r.Header.Get("TimeRequested")
	if strTime != "" {
		intTime, err = strconv.Atoi(strTime)
		if err != nil {
			log.Print("error geting time from request: creating token: ", err)
		}
	} else {
		intTime = 30
	}
	task := r.Header.Get("Task")

	expirationTime := time.Now().Add(time.Minute * time.Duration(intTime)).Unix()

	atClaims := jwt.MapClaims{}
	atClaims["Authorized"] = true
	atClaims["id"] = user.Id
	atClaims["username"] = user.UserName
	atClaims["rol"] = user.Rol
	atClaims["email"] = user.Email
	atClaims["exp"] = expirationTime
	atClaims["host"] = r.Host
	atClaims["remoteaddr"] = r.RemoteAddr
	atClaims["task"] = task
	t := jwt.New(jwt.SigningMethodRS512)
	t.Claims = &atClaims

	atString, err := t.SignedString(signedKey)

	if err != nil {
		log.Print("error firmando llave: ", err)
	}
	return atString
}

// Validador Externo del token
func ExternalValidator(Rtoken string) ([]byte, error) {

	verifyBytes, err := ioutil.ReadFile(keysDir + "pubRsaKey.pub")
	if err != nil {
		log.Print("Error reading public key: ", err)
	}

	verifyPubKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Print("Error verifying public key: ", err, verifyPubKey)
		return nil, err
	}

	token, err := jwt.ParseWithClaims(Rtoken, &costumClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyPubKey, nil
	})
	if err != nil {
		log.Print("Auth: middleware: validate token: parse Token: ", err)

		return nil, err
	}

	claims := token.Claims
	jclaims, err := json.Marshal(claims)
	if err != nil {
		log.Print("parsing claims: ", err)
	}
	// Hasta aqui el token es valido y esta correcto
	info := userInfo{}
	err = json.Unmarshal(jclaims, &info)
	if err != nil {
		log.Print("parsing other claims: ", err)
	}

	return jclaims, nil

}

func ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val := r.Header.Get("Authorization"); val == "" {
			if r.Method == "PUT" || r.Method == "DELETE" || r.Method == "GET" {
				http.Error(w, "Authentication required!!", http.StatusUnauthorized)
				return
			}
			log.Print("in midleware", r.Header.Get("Authorization"))
			r.Header.Set("claims", "")
			next.ServeHTTP(w, r)
			return
		}
		//		log.Print("dentro de dentro de middleware")
		bearer := r.Header.Get("Authorization")
		value := bearer[len("bearer "):]
		//log.Print(token)

		verifyBytes, err := ioutil.ReadFile(keysDir + "pubRsaKey.pub")
		if err != nil {
			log.Print("Error reading public key: ", err)
		}

		verifyPubKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			log.Print("Error verifying public key: ", err, verifyPubKey)
			return
		}

		token, err := jwt.ParseWithClaims(value, &costumClaims{}, func(token *jwt.Token) (interface{}, error) {
			return verifyPubKey, nil
		})
		if err != nil {
			log.Print("Auth: middleware: validate token: parse Token: ", err)
			r.Header.Set("Authenticated", "false")
			next.ServeHTTP(w, r)
			return
		}

		claims := token.Claims
		jclaims, err := json.Marshal(claims)
		if err != nil {
			log.Print("parsing claims: ", err)
		}
		// Hasta aqui el token es valido y esta correcto
		info := userInfo{}
		err = json.Unmarshal(jclaims, &info)
		if err != nil {
			log.Print("parsing other claims: ", err)
		}
		// comprobamos los origenes y destinos del token
		if strings.Split(info.Remoteaddr, ":")[0] != strings.Split(r.RemoteAddr, ":")[0] {
			log.Print("ADDRSS no concuerdan", info.Remoteaddr, " : ", r.RemoteAddr)
			http.Error(w, "Destination Error!", http.StatusForbidden)
			return
		}
		r.Header.Set("claims", string(jclaims))
		next.ServeHTTP(w, r)
	})

}

func ValidateAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Header.Get("claims")
		if claims == "" {
			http.Error(w, "Authentication required!", http.StatusUnauthorized)
			return
		}
		user := db.User{}
		err := json.Unmarshal([]byte(claims), &user)
		if err != nil {
			log.Print("Auth: ValidateAdmin: UserCreation: ", err)
		}

		if user.Rol != "admin" {
			http.Error(w, "Priviledges are required!", http.StatusForbidden)
			return
		}
		r.Header.Set("isAdmin", "true")
		next.ServeHTTP(w, r)
	})
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originEnv := os.Getenv("DEVORIGINLIST")
		originSlice := strings.Split(originEnv, ",")

		isInList := false
		origin := r.Header.Get("Origin")
		// itermos sobre los origenes si lo encontramos Break
		for _, origi := range originSlice {
			if origi == origin {
				isInList = true
				break
			} else {
				isInList = false
			}
		}
		// si el origen esta en la lista setea los headers
		if isInList {
			w.Header().Set("Content-Type", "text/html; charset=ascii")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,access-control-allow-origin, access-control-allow-headers")
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE")

			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization")
			return
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
