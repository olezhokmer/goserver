package main

import (
	"context"
	"crypto/md5"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/streadway/amqp"
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
func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func main() {
	r := mux.NewRouter()

	conn, conErr := amqp.Dial("amqp://guest:guest@localhost:5672/")
	failOnError(conErr, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, chErr := conn.Channel()
	failOnError(chErr, "Failed to open a channel")
	defer ch.Close()

	q, qErr := ch.QueueDeclare(
		"hello", // name
		false,   // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	failOnError(qErr, "Failed to declare a queue")

	rbqService := NewRbqService(ch, q)
	userService := NewUserService(rbqService)
	jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
	userService.createSuperAdmin()
	if jwtErr != nil {
		panic(jwtErr)
	}
	hub := newHub()
	go hub.run()

	r.HandleFunc("/admin/socket", jwtService.jwtAuthSocket(userService, hub))
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
	msgs, consErr := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(consErr, "Failed to register a consumer")

	go func() {
		for d := range msgs {
			log.Printf("Received a message: %s", d.Body)
		}
	}()

	err := srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}
