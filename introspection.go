package traefik_plugin_keycloak_oauth2_introspection

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type Config struct {
	KeycloakIntrospectionEndpoint *string
	ClientID                      *string
	ClientSecret                  *string
	RealmRoles                    *([]string)
	ClientRoles                   *(map[string]([]string))
}

type ResponseRoles struct {
	Roles []string `json:"roles"`
}

type Response struct {
	Active         *bool                    `json:"active"`
	RealmAccess    ResponseRoles            `json:"realm_access"`
	ResourceAccess map[string]ResponseRoles `json:"resource_access"`
}

func CreateConfig() *Config {
	return &Config{
		KeycloakIntrospectionEndpoint: nil,
		ClientID:                      nil,
		ClientSecret:                  nil,
		RealmRoles:                    nil,
		ClientRoles:                   nil,
	}
}

type Plugin struct {
	next         http.Handler
	endpoint     string
	clientId     string
	clientSecret string
	realmRoles   []string
	clientRoles  map[string]([]string)
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
	if (*config).ClientID == nil {
		errs = append(errs, "ClientID not set")
	}
	if (*config).ClientSecret == nil {
		errs = append(errs, "ClientSecret not set")
	}
	if len(errs) != 0 {
		return nil, errors.New(strings.Join(errs, ", "))
	}
	realmRoles := []string{}
	if (*config).RealmRoles != nil {
		realmRoles = *((*config).RealmRoles)
	}
	clientRoles := map[string]([]string){}
	if (*config).ClientRoles != nil {
		clientRoles = *((*config).ClientRoles)
	}
	return &Plugin{
		next:         next,
		endpoint:     *((*config).KeycloakIntrospectionEndpoint),
		clientId:     *((*config).ClientID),
		clientSecret: *((*config).ClientSecret),
		realmRoles:   realmRoles,
		clientRoles:  clientRoles,
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
		http.Error(rw, "unmarshall", http.StatusInternalServerError)
		return
	}
	if s.Active == nil || *(s.Active) == false {
		http.Error(rw, "not active token", http.StatusUnauthorized)
		return
	}
	var errs []string = []string{}
	for _, r := range a.realmRoles {
		if !slices.Contains(s.RealmAccess.Roles, r) {
			errs = append(errs, r)
		}
	}
	for cfgCRkey, cfgCRval := range a.clientRoles {
		tokenCRval, tokenCRok := s.ResourceAccess[cfgCRkey]
		if tokenCRok {
			for _, crv := range cfgCRval {
				if !slices.Contains(tokenCRval.Roles, crv) {
					errs = append(errs, "cfgCRkey:"+crv)
				}
			}
		} else {
			errs = append(errs, "cfgCRkey:("+strings.Join(cfgCRval, "|")+")")
		}
	}
	if len(errs) != 0 {
		http.Error(rw, "missing roles: "+strings.Join(errs, ", "), http.StatusForbidden)
		return
	}
	a.next.ServeHTTP(rw, req)
}
