package main

import "github.com/streadway/amqp"

type RbqService struct {
	ch *amqp.Channel
	q  amqp.Queue
}

func NewRbqService(ch *amqp.Channel, q amqp.Queue) *RbqService {
	return &RbqService{
		ch: ch,
		q:  q,
	}
}

func (s *RbqService) sendMsg(msg string) error {
	return s.ch.Publish(
		"",       // exchange
		s.q.Name, // routing key
		false,    // mandatory
		false,    // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(msg),
		},
	)
}
