package main

import (
	"errors"
	"sync"
)

type BanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type Ban struct {
	Email  string
	Reason string
}
type InMemoryBanHistoryStorage struct {
	lock    sync.RWMutex
	storage map[string]string
}

func NewInMemoryBanHistoryStorage() *InMemoryBanHistoryStorage {
	return &InMemoryBanHistoryStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]string),
	}
}

type BanHistoryRepository interface {
	Add(string, string) error
	GetHistory(string) (string, error)
	DeleteHistory(string) error
}

func (s *InMemoryBanHistoryStorage) Add(email string, event string) error {
	if len(s.storage[email]) == 0 {
		s.storage[email] = event
	} else {
		s.storage[email] = s.storage[email] + event
	}
	return nil
}

func (s *InMemoryBanHistoryStorage) GetHistory(email string) (string, error) {
	return s.storage[email], nil
}

func (s *InMemoryBanHistoryStorage) DeleteHistory(email string) error {
	if len(s.storage[email]) == 0 {
		return errors.New("No history.")
	}
	delete(s.storage, email)
	return nil
}
