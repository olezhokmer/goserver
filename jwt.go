package main

import (
	"net/http"
	"strings"

	"github.com/openware/rango/pkg/auth"
)

type JWTService struct {
	keys *auth.KeyStore
}

func NewJWTService(privKeyPath, pubKeyPath string) (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTService{keys: keys}, nil
}

func (j *JWTService) GenearateJWT(u User) (string, error) {
	return auth.ForgeToken("empty", u.Email, "empty", 0, j.keys.PrivateKey, nil)
}
func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func wrapJwt(jwt *JWTService, f func(http.ResponseWriter, *http.Request, *JWTService)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f(rw, r, jwt)
	}
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User)

func (j *JWTService) jwtAuth(userService *UserService, h ProtectedHandler) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(401)
			rw.Write([]byte("unauthorized"))
			return
		}
		user, err := userService.repository.Get(auth.Email)
		if err != nil || len(user.Email) == 0 {
			rw.WriteHeader(401)
			rw.Write([]byte("unauthorized"))
			return
		}
		reason, banErr := userService.getBanReason(user.Email)
		if banErr == nil {
			rw.WriteHeader(401)
			rw.Write([]byte(reason))
			return
		}
		h(rw, r, user)
	}
}
