package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("secrey_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claim struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	var credential Credential

	err := json.NewDecoder(r.Body).Decode(&credential)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[credential.Username]

	if !ok || expectedPassword != credential.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ExpiresAt := jwt.NewNumericDate(time.Now().Add(time.Minute * 5))

	claim := &Claim{
		Username: credential.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: ExpiresAt,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}{
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(ExpiresAt.Time).Seconds()),
		AccessToken: tokenString,
	})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")

	if len(splitToken) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimSpace(splitToken[1])

	claim := &Claim{}

	token, err := jwt.ParseWithClaims(tokenStr, claim, func(t *jwt.Token) (interface{}, error) {
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

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Until(claim.ExpiresAt.Time).Seconds() < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ExpiresAt := jwt.NewNumericDate(time.Now().Add(time.Minute * 5))

	claim.ExpiresAt = ExpiresAt

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}{
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(ExpiresAt.Time).Seconds()),
		AccessToken: tokenString,
	})
}

func GetResources(w http.ResponseWriter, r *http.Request) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")

	if len(splitToken) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimSpace(splitToken[1])

	claim := &Claim{}

	token, err := jwt.ParseWithClaims(tokenStr, claim, func(t *jwt.Token) (interface{}, error) {
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

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s", claim.Username)))
}
