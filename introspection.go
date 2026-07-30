package traefik_plugin_keycloak_oauth2_introspection

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	//"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type Config struct {
	// intro
	KeycloakIntrospectionEndpoint *string
	ClientID                      *string
	ClientSecret                  *string
	// cert
	KeycloakCertsEndpoint *string
	ExpectedIssuer        string
	// common
	RealmRoles  *([]string)
	ClientRoles *(map[string]([]string))
	Method      string
}

type ResponseRoles struct {
	Roles []string `json:"roles"`
}

type Response struct {
	Active         *bool                    `json:"active"`
	RealmAccess    ResponseRoles            `json:"realm_access"`
	ResourceAccess map[string]ResponseRoles `json:"resource_access"`
}

type JWTHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type JWTClaims struct {
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
	Aud any    `json:"aud"` // Can be string or array of strings
}

type Key struct {
	Alg string   `json:"alg"`
	E   string   `json:"e"`
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	N   string   `json:"n"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	//X5tS256 string   `json:"x5t#S256"`
}

type CertsResponse struct {
	Keys []Key `json:"keys"`
}

func CreateConfig() *Config {
	return &Config{
		KeycloakIntrospectionEndpoint: nil,
		ClientID:                      nil,
		ClientSecret:                  nil,
		KeycloakCertsEndpoint:         nil,
		ExpectedIssuer:                "",
		RealmRoles:                    nil,
		ClientRoles:                   nil,
		Method:                        "",
	}
}

type PluginIntrospection struct {
	next         http.Handler
	endpoint     string
	clientId     string
	clientSecret string
	realmRoles   []string
	clientRoles  map[string]([]string)
	httpClient   *http.Client
}

type PluginSignature struct {
	next           http.Handler
	certs          CertsResponse
	expectedIssuer string
	realmRoles     []string
	clientRoles    map[string]([]string)
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var errs []string = []string{}
	var handler http.Handler

	// common
	realmRoles := []string{}
	if (*config).RealmRoles != nil {
		realmRoles = *((*config).RealmRoles)
	}
	clientRoles := map[string]([]string){}
	if (*config).ClientRoles != nil {
		clientRoles = *((*config).ClientRoles)
	}

	switch (*config).Method {
	case "introspection":
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
		handler = &PluginIntrospection{
			next:         next,
			endpoint:     *((*config).KeycloakIntrospectionEndpoint),
			clientId:     *((*config).ClientID),
			clientSecret: *((*config).ClientSecret),
			realmRoles:   realmRoles,
			clientRoles:  clientRoles,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
	case "signature":
		certs := CertsResponse{}
		if (*config).KeycloakCertsEndpoint == nil {
			errs = append(errs, "KeycloakCertsEndpoint not set")
		} else {
			resp, err := http.Get(*((*config).KeycloakCertsEndpoint))
			if err != nil {
				errs = append(errs, "http.Get error")
			} else {
				defer resp.Body.Close()
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					errs = append(errs, "io.ReadAll(resp.Body)")
				} else {
					var s CertsResponse
					err = json.Unmarshal(bodyBytes, &s)
					if err != nil {
						errs = append(errs, "json.Unmarshal(bodyBytes, &s)")
					} else {
						certs = s
					}
				}
			}
		}
		handler = &PluginSignature{
			next:           next,
			certs:          certs,
			expectedIssuer: (*config).ExpectedIssuer,
			realmRoles:     realmRoles,
			clientRoles:    clientRoles,
		}
	default:
		errs = append(errs, "invalid Method")
	}
	if len(errs) != 0 {
		return nil, errors.New(strings.Join(errs, ", "))
	}
	return handler, nil
}

func (a *PluginIntrospection) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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
					errs = append(errs, cfgCRkey+":"+crv)
				}
			}
		} else {
			errs = append(errs, cfgCRkey+":("+strings.Join(cfgCRval, "|")+")")
		}
	}
	if len(errs) != 0 {
		http.Error(rw, "missing roles: "+strings.Join(errs, ", "), http.StatusForbidden)
		return
	}
	a.next.ServeHTTP(rw, req)
}

func DecodeBase64URL(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

func (a *PluginSignature) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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
	token := strings.TrimPrefix(authHeader, prefix)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		http.Error(rw, "invalid token format", http.StatusBadRequest)
		return
	}
	headerPart, payloadPart, signaturePart := parts[0], parts[1], parts[2]
	// 1. Parse Header to get Key ID (kid)
	headerBytes, err := DecodeBase64URL(headerPart)
	if err != nil {
		http.Error(rw, "failed to decode header", http.StatusInternalServerError)
		return
	}
	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		http.Error(rw, "failed to unmarshal header", http.StatusInternalServerError)
		return
	}
	if header.Alg != "RS256" {
		http.Error(rw, "unsupported algorithm: "+header.Alg, http.StatusBadRequest)
		return
	}
	// 2. Parse and Validate Payload Claims
	payloadBytes, err := DecodeBase64URL(payloadPart)
	if err != nil {
		http.Error(rw, "failed to decode payload", http.StatusInternalServerError)
		return
	}
	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		http.Error(rw, "failed to unmarshal claims", http.StatusInternalServerError)
		return
	}
	if time.Now().Unix() > claims.Exp {
		http.Error(rw, "token has expired", http.StatusUnauthorized)
		return
	}
	if claims.Iss != a.expectedIssuer {
		http.Error(rw, "invalid issuer: got "+claims.Iss+", want "+a.expectedIssuer, http.StatusUnauthorized)
		return
	}
	// 3. Find matching JWK
	var targetKey *Key
	for _, key := range a.certs.Keys {
		if key.Kid == header.Kid {
			targetKey = &key
			break
		}
	}
	if targetKey == nil {
		http.Error(rw, "corresponding public key not found in JWKS", http.StatusUnauthorized)
		return
	}
	// 4. Reconstruct RSA Public Key from JWK Modulus (n) and Exponent (e)
	nBytes, err := DecodeBase64URL(targetKey.N)
	if err != nil {
		http.Error(rw, "failed to decode modulus", http.StatusInternalServerError)
		return
	}
	eBytes, err := DecodeBase64URL(targetKey.E)
	if err != nil {
		http.Error(rw, "failed to decode exponent", http.StatusInternalServerError)
		return
	}
	var eVal int
	for _, b := range eBytes {
		eVal = (eVal << 8) + int(b)
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eVal,
	}
	// 5. Verify Cryptographic Signature
	sigBytes, err := DecodeBase64URL(signaturePart)
	if err != nil {
		http.Error(rw, "failed to decode signature", http.StatusInternalServerError)
		return
	}
	// Signature covers "header.payload"
	signedData := []byte(headerPart + "." + payloadPart)
	hashed := sha256.Sum256(signedData)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		http.Error(rw, "signature verification failed", http.StatusUnauthorized)
		return
	}
	a.next.ServeHTTP(rw, req)
}
