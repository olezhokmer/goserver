package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
	"crypto/md5"

	"github.com/gorilla/mux"
)


func (u *UserService) createSuperAdmin() {
	superadmin := User{
		Email:          "superadmin@gmail.com",
		PasswordDigest: string(md5.New().Sum([]byte("12345678"))),
		Role:           "superadmin",
		FavoriteCake:   "a",
	}
	u.repository.Add("superadmin@gmail.com", superadmin)
}

func (u *UserService) createAdmin() {
	admin := User{
		Email:          "admin@gmail.com",
		PasswordDigest: string(md5.New().Sum([]byte("12345678"))),
		Role:           "admin",
		FavoriteCake:   "a",
	}
	u.repository.Add("admin@gmail.com", admin)
}

func main() {
	r := mux.NewRouter()

	userService := NewUserService()
	jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
	userService.createSuperAdmin()
	if jwtErr != nil {
		panic(jwtErr)
	}

	r.HandleFunc("/user/register", logRequest(userService.Register)).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, userService.JWT))).Methods(http.MethodPost)
	r.HandleFunc("/cake", logRequest(jwtService.jwtAuth(userService, getCakeHandler))).Methods(http.MethodGet)
	r.HandleFunc("/user/me", logRequest(jwtService.jwtAuth(userService, userService.getUserInformation))).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", logRequest(jwtService.jwtAuth(userService, userService.updateCake))).Methods(http.MethodPut)
	r.HandleFunc("/user/email", logRequest(jwtService.jwtAuth(userService, userService.updateEmail))).Methods(http.MethodPut)
	r.HandleFunc("/user/password", logRequest(jwtService.jwtAuth(userService, userService.updatePassword))).Methods(http.MethodPut)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAuth(userService, userService.inspect))).Methods(http.MethodPost)
	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAuth(userService, userService.ban))).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAuth(userService, userService.unban))).Methods(http.MethodPost)

	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Println("Server started, hit Ctrl+C to stop")
	err := srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}
