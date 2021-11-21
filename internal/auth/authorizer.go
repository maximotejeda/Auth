package auth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
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

// corre al importar
func init() {
	netrsakeys.GenerateKeyPair("keys/")
}

// Creamos un token
func createToken(user *db.User, r *http.Request) string {
	var err error
	// get private key
	file, err := ioutil.ReadFile("keys/privateRSAKey")
	if err != nil {
		log.Print("Error reading Secret key", err)
	}
	signedKey, err := jwt.ParseRSAPrivateKeyFromPEM(file)
	if err != nil {
		log.Print("Error reading Secret key", err)
	}

	verifyBytes, err := ioutil.ReadFile("keys/pubRsaKey.pub")
	if err != nil {
		log.Print("Error reading public key: ", err)
	}

	verifyPubKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Print("Error verifying public key: ", err, verifyPubKey)
		return ""
	}

	atClaims := jwt.MapClaims{}
	atClaims["Authorized"] = true
	atClaims["id"] = user.Id
	atClaims["username"] = user.UserName
	atClaims["rol"] = user.Rol
	atClaims["email"] = user.Email
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	atClaims["host"] = r.Host
	atClaims["remoteaddr"] = r.RemoteAddr

	t := jwt.New(jwt.SigningMethodRS512)
	t.Claims = &atClaims
	atString, err := t.SignedString(signedKey)

	if err != nil {
		log.Print("error firmando llave: ", err)
	}
	return atString
}

func ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val := r.Header.Get("Authorization"); val == "" {
			if r.Method == "PUT" || r.Method == "DELETE" || r.Method == "GET" {
				http.Error(w, "Authentication required!", http.StatusUnauthorized)
				return
			}
			r.Header.Set("claims", "")
			next.ServeHTTP(w, r)
			return
		}
		//		log.Print("dentro de dentro de middleware")
		bearer := r.Header.Get("Authorization")
		value := bearer[len("bearer "):]
		//log.Print(token)

		verifyBytes, err := ioutil.ReadFile("keys/pubRsaKey.pub")
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
		if info.Remoteaddr != r.RemoteAddr {
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
