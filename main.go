package main

import (
    "fmt"
    "log"
    "encoding/json"
    "net/http"
    "os"
    "strconv"
    "time"

    "github.com/dgrijalva/jwt-go"
)

const validTokenTime = 5

var jwtKey = []byte(os.Getenv("jwt_key"))

var users = map[string]string{
    os.Getenv("user_name"): os.Getenv("user_pass"),
}

type Credentials struct{
    Password string `json:"password"`
    Username string `json:"username"`
}

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

type ResponseJson struct {
    Return string `json:"value"`
}

type ResponseJsonList struct {
    field []ResponseJson `json:"field"`
}

func Signin(w http.ResponseWriter, r *http.Request) {
    var creds Credentials

    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    dbPass := users[creds.Username]

    if dbPass == "" || dbPass != creds.Password {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(validTokenTime * time.Minute)

    claims := &Claims{
        Username: creds.Username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    tokenString, err:= token.SignedString(jwtKey)

    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name: "token",
        Value: tokenString,
        Expires: expirationTime,
    })
}

func handlerCheck(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")
    fmt.Fprintf(w, "golang")
}

func handlerHost(w http.ResponseWriter, r *http.Request) {
    hostname, err := os.Hostname()
    if err != nil {
        panic(err)
    }
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")

    resJson := ResponseJson{hostname}
    newsJson, err := json.Marshal(resJson)
    if err != nil {
        panic(err)
    }
    w.Write(newsJson)
}

func handlerNumber(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    fmt.Println(r)
    fmt.Println(r.Form)
    var ret int
    if r.Form["number"] != nil {
        ret, _ = strconv.Atoi(r.Form["number"][0])
        ret*=2
    } else {
        ret = 0
    }
    resJson := ResponseJson{strconv.Itoa(ret)}
    newsJson, err := json.Marshal(resJson)
    if err != nil {
        panic(err)
    }
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")
    w.Write(newsJson)
}

func handlerEnv(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")
    resJson := ResponseJson{os.Getenv("go_var")}
    newsJson, err := json.Marshal(resJson)
    if err != nil {
        panic(err)
    }
    w.Write(newsJson)
}

func handlerJSON(w http.ResponseWriter, r *http.Request) {
    resJson := ResponseJson{"80"}

    newsJson, err := json.Marshal(resJson)
    if err != nil {
        panic(err)
    }

    fmt.Println(string(newsJson))
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")

    w.Write(newsJson)
}

func handlerVersion(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("access-control-allow-origin", "*")
    w.Header().Set("access-control-allow-methods", "GET, PUT, DELETE, POST, OPTIONS")
    w.Header().Set("access-control-allow-headers", "x-algolia-application-id, connection, origin, x-algolia-api-key, content-type, content-length, x-algolia-signature, x-algolia-usertoken, x-algolia-tagfilters, DNT, X-Mx-ReqToken, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Authorization, Accept")
    w.Header().Set("access-control-allow-credentials", "false")
    fmt.Fprintf(w, "REPLACE_THIS_BY_VERSION_NUMBER")
}

func Welcome(w http.ResponseWriter, r *http.Request) {
    // We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func main() {
    http.HandleFunc("/check", handlerCheck)
    http.HandleFunc("/status", handlerCheck)
    http.HandleFunc("/v1/check", handlerCheck)
    http.HandleFunc("/v1/status", handlerCheck)
    http.HandleFunc("/v1/host", handlerHost)
    http.HandleFunc("/v1/number", handlerNumber)
    http.HandleFunc("/v1/env", handlerEnv)
    http.HandleFunc("/v1/json", handlerJSON)
    http.HandleFunc("/v1/version", handlerVersion)
    http.HandleFunc("/v1/signin", Signin)
    http.HandleFunc("/v1/admin", Welcome)
    log.Fatal(http.ListenAndServe(":8080", nil))
}