package myplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	KeycloakIntrospectionEndpoint *string
	ClientID                      *string
	ClientSecret                  *string
}

type Response struct {
	Active *bool `json:"active"`
	// add permissions if you want to also validate roles
}

func CreateConfig() *Config {
	return &Config{
		KeycloakIntrospectionEndpoint: nil,
		ClientID:                      nil,
		ClientSecret:                  nil,
	}
}

type Plugin struct {
	next         http.Handler
	endpoint     string
	clientId     string
	clientSecret string
	httpClient   *http.Client
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var errs []string = []string{}
	if (*config).KeycloakIntrospectionEndpoint == nil {
		errs = append(errs, "KeycloakIntrospectionEndpoint not set")
	} else {
		_, err := url.ParseRequestURI(*((*config).KeycloakIntrospectionEndpoint))
		if err != nil {
			errs = append(errs, "KeycloakIntrospectionEndpoint no es uri valida?")
		}
	}
	if (*config).KeycloakIntrospectionEndpoint == nil {
		errs = append(errs, "ClientID not set")
	}
	if (*config).KeycloakIntrospectionEndpoint == nil {
		errs = append(errs, "ClientSecret not set")
	}
	if len(errs) != 0 {
		return nil, errors.New(strings.Join(errs, ", "))
	}
	return &Plugin{
		next:         next,
		endpoint:     *((*config).KeycloakIntrospectionEndpoint),
		clientId:     *((*config).ClientID),
		clientSecret: *((*config).ClientSecret),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (a *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(rw, "authorization header missing", http.StatusBadRequest)
		return
	}
	prefix := "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		http.Error(rw, "authorization header malformed: expected 'Bearer ' prefix", http.StatusBadRequest)
		return
	}
	req, err := http.NewRequest("POST", a.endpoint, nil)
	if err != nil {
		http.Error(rw, "request create error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", `application/x-www-form-urlencoded`)
	req.SetBasicAuth(a.clientId, a.clientSecret)
	req.Body = io.NopCloser(strings.NewReader("token=" + strings.TrimPrefix(authHeader, prefix)))
	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(rw, "request perform error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(rw, "reading response body", http.StatusInternalServerError)
		return
	}
	var s Response
	err = json.Unmarshal(bodyBytes, &s)
	if err != nil {
		fmt.Println("\n\n", err, string(bodyBytes), "\n\n")
		http.Error(rw, "unmarshall", http.StatusInternalServerError)
		return
	}
	if s.Active == nil || *(s.Active) == false {
		fmt.Println("\n\n", string(bodyBytes), "\n\n")
		http.Error(rw, "not active: ", http.StatusUnauthorized)
		return
	}
	a.next.ServeHTTP(rw, req)
}
