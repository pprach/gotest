package main

import (
    "fmt"
    "log"
    "encoding/json"
    "net/http"
    "os"
    "strconv"
)

type ResponseJson struct {
    Return string `json:"value"`
}

type ResponseJsonList struct {
    field []ResponseJson `json:"field"`
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
    resJson := ResponseJson{"81"}

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
    log.Fatal(http.ListenAndServe(":8080", nil))
}
