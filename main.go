package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/zitadel/oidc/pkg/client/rs"
	"github.com/zitadel/oidc/pkg/oidc"
)

const (
	publicURL          string = "/public"
	protectedURL       string = "/protected"
	protectedClaimURL  string = "/protected/{claim}/{value}"
	protectedStandards string = "/protected-standards"
	protectedRoles     string = "/protected-roles"
)

func main() {
	//keyPath := os.Getenv("KEY")
	client := "mybackend"
	secret := "367d0e61-dc7a-416e-8d14-17dee1b06b1e"
	port := 8082
	issuer := "http://localhost:8081/auth/realms/myrealm"

	//provider, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	provider, err := rs.NewResourceServerClientCredentials(issuer, client, secret)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	router := mux.NewRouter()

	//public url accessible without any authorization
	//will print `OK` and current timestamp
	router.HandleFunc(publicURL, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK " + time.Now().String()))
	})

	//protected url which needs an active token
	//will print the result of the introspection endpoint on success
	router.HandleFunc(protectedURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect(r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	//protected url which needs an active token and checks if the response of the introspect endpoint
	//contains a requested claim with the required (string) value
	//e.g. /protected/username/livio@caos.ch
	router.HandleFunc(protectedClaimURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect(r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		params := mux.Vars(r)
		requestedClaim := params["claim"]
		requestedValue := params["value"]
		value, ok := resp.GetClaim(requestedClaim).(string)
		if !ok || value == "" || value != requestedValue {
			http.Error(w, "claim does not match", http.StatusForbidden)
			return
		}
		w.Write([]byte("authorized with value " + value))
	})

	router.HandleFunc(protectedStandards, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect(r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		outputs := make([]string, 0)
		outputs = append(outputs, fmt.Sprintf("Birthday=%s", resp.GetBirthdate()))
		outputs = append(outputs, fmt.Sprintf("Email=%s", resp.GetEmail()))
		outputs = append(outputs, fmt.Sprintf("Gender=%s", resp.GetGender()))
		outputs = append(outputs, fmt.Sprintf("Picture=%s", resp.GetPicture()))
		outputs = append(outputs, fmt.Sprintf("Subject=%s", resp.GetSubject()))
		outputs = append(outputs, fmt.Sprintf("Email Verified=%t", resp.IsEmailVerified()))

		w.Write([]byte(strings.Join(outputs, "\n")))
	})

	router.HandleFunc(protectedRoles, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect(r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// type clientRoles map[string][]string
		// type accesses = map[string]clientRoles
		aa, ok := resp.GetClaim("resource_access").(map[string]interface{})
		if !ok {
			http.Error(w, "cannot retrieve resource_access", http.StatusForbidden)
			return
		}

		c, ok := aa["account"].(map[string]interface{})
		if !ok {
			http.Error(w, "cannot retrieve account resource_access", http.StatusForbidden)
			return
		}

		roles, ok := c["roles"].([]interface{})
		if !ok {
			http.Error(w, "cannot retrieve account resource_access", http.StatusForbidden)
			return
		}

		a := make([]string, len(roles))
		for i, item := range roles {
			a[i] = item.(string)
		}

		//a, ok := resp.GetClaim("resource_access").(string)
		// ao := resp.GetClaim("allowed-origins").([]interface{})
		// a := make([]string, len(ao))
		// for i, _ := range ao {
		// 	a[i] = ao[i].(string)
		// }

		value, err := json.Marshal(a)

		w.Write(value)
	})

	lis := fmt.Sprintf("127.0.0.1:%d", port)
	log.Printf("listening on http://%s/", lis)
	log.Fatal(http.ListenAndServe(lis, router))
}

func checkToken(w http.ResponseWriter, r *http.Request) (bool, string) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return false, ""
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return false, ""
	}
	return true, strings.TrimPrefix(auth, oidc.PrefixBearer)
}
