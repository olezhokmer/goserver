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
		s.storage[email] = s.storage[email] + "\n" + event
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

type InMemoryUserStorage struct {
	lock    sync.RWMutex
	storage map[string]User
}

func NewInMemoryUserStorage() *InMemoryUserStorage {
	return &InMemoryUserStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]User),
	}
}

type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

func (s *InMemoryUserStorage) Add(email string, data User) error {
	if len(s.storage[email].Email) != 0 {
		return errors.New("User exists.")
	}
	s.storage[email] = data
	return nil
}

func (s *InMemoryUserStorage) Get(email string) (User, error) {
	// if len(s.storage[email].Email) == 0 {
	// 	return User{}, errors.New("User not found.")
	// }
	return s.storage[email], nil
}
func (s *InMemoryUserStorage) Update(email string, user User) error {
	if len(s.storage[email].Email) == 0 {
		return errors.New("User not found.")
	}
	delete(s.storage, email)
	s.storage[user.Email] = user
	return nil
}
func (s *InMemoryUserStorage) Delete(email string) (User, error) {
	if len(s.storage[email].Email) != 0 {
		return User{}, errors.New("User not found.")
	}
	user := s.storage[email]
	delete(s.storage, email)
	return user, nil
}
