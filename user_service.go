package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type UserService struct {
	repository           UserRepository
	banHistoryRepository BanHistoryRepository
}

func NewUserService() *UserService {
	return &UserService{
		repository:           NewInMemoryUserStorage(),
		banHistoryRepository: NewInMemoryBanHistoryStorage(),
	}
}

func (u *UserService) validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("Invalid email.")
	} else {
		return nil
	}
}

func (u *UserService) validatePass(pass string) error {
	if len(pass) < 8 {
		return errors.New("Password is too simple.")
	} else {
		return nil
	}
}

func (u *UserService) validateCake(cake string) error {
	if len(strings.TrimSpace(cake)) == 0 {
		return errors.New("Empty cake.")
	}
	for _, char := range cake {
		if !unicode.IsLetter(char) {
			return errors.New("Cake must contain only latters.")
		}
	}
	return nil
}
func (u *UserService) validateBanReason(r string) error {
	if len(strings.TrimSpace(r)) == 0 {
		return errors.New("Empty cake.")
	}
	return nil
}

func (u *UserService) validateRegisterParams(p *UserRegisterParams) error {
	err := u.validateEmail(p.Email)
	if err != nil {
		return err
	}
	err = u.validatePass(p.Password)
	if err != nil {
		return err
	}
	err = u.validateCake(p.FavoriteCake)
	if err != nil {
		return err
	}
	return nil
}
func (u *UserService) validateBanParams(p *BanParams) error {
	err := u.validateEmail(p.Email)
	if err != nil {
		return err
	}
	err = u.validateBanReason(p.Reason)
	if err != nil {
		return err
	}
	return nil
}
func (u *UserService) hasEnoughRights(admin User, user User) bool {
	if admin.Role != "admin" || admin.Role != "superadmin" || user.Role == admin.Role || user.Role == "superadmin" {
		return false
	}
	return true
}

// func (u *UserService) getBanReason(email string) (string, error) {
// 	history, err := u.banHistoryRepository.GetHistory(email)
// 	if err != nil {
// 		return "", err
// 	}
// 	events := strings.Split(history, "\n")
// 	if len(events) != 0 {
// 		return "", errors.New("User has empty history.")
// 	}

// 	last := events[len(events)-1]
// 	if strings.Contains(last, "Ban") != true {
// 		return "", errors.New("User is not baned.")
// 	} else {
// 		splited := strings.Split(history, ".")
// 		reason := splited[len(splited)-1]
// 		return reason, nil
// 	}
// }
func (u *UserService) ban(w http.ResponseWriter, r *http.Request, user User) {
	params := &BanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := u.validateBanParams(params); err != nil {
		handleError(err, w)
		return
	}
	_, findErr := u.repository.Get(params.Email)
	if findErr != nil {
		handleError(findErr, w)
		return
	}

	// reason, _ := u.getBanReason(params.Email)
	// if len(reason) != 0 {
	// 	handleError(errors.New("User already baned. Reason: "+reason), w)
	// 	return
	// }
	// if u.hasEnoughRights(user, userToBan) == false {
	// 	w.WriteHeader(401)
	// 	w.Write([]byte("Access denied."))
	// 	return
	// }

	event := "Ban by " + user.Email + ". " + params.Reason + "\n"
	u.banHistoryRepository.Add(params.Email, event)

	w.Write([]byte("Success."))
}

func (u *UserService) unban(w http.ResponseWriter, r *http.Request, user User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	email := string(res)

	err = u.validateEmail(email)
	if err != nil {
		handleError(err, w)
		return
	}
	_, findErr := u.repository.Get(email)
	if findErr != nil {
		handleError(findErr, w)
		return
	}

	// reason, _ := u.getBanReason(email)
	// if len(strings.TrimSpace(reason)) != 0 {
	// 	handleError(errors.New("User banned. Reason: "+reason), w)
	// 	return
	// }
	// if u.hasEnoughRights(user, userToBan) == false {
	// 	w.WriteHeader(401)
	// 	w.Write([]byte("Access denied."))
	// 	return
	// }

	event := "Unbaned by " + user.Email + " at " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"
	u.banHistoryRepository.Add(email, event)

	w.Write([]byte("Success."))
}

func (u *UserService) inspect(w http.ResponseWriter, r *http.Request, user User) {
	var buf []byte
	res, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	email := string(res)

	err = u.validateEmail(email)
	if err != nil {
		handleError(err, w)
		return
	}

	userToInspect, findErr := u.repository.Get(email)
	if findErr != nil {
		handleError(findErr, w)
		return
	}

	// if u.hasEnoughRights(user, userToInspect) == false {
	// 	w.WriteHeader(401)
	// 	w.Write([]byte("Access denied."))
	// 	return
	// }
	history, historyErr := u.banHistoryRepository.GetHistory(userToInspect.Email)
	if historyErr != nil {
		handleError(findErr, w)
		return
	}

	inspectInfo := &InspectInfo{
		Email:        user.Email,
		FavoriteCake: user.FavoriteCake,
		Role:         user.Role,
		History:      history,
	}
	buf, err = json.Marshal(inspectInfo)
	if err != nil {
		handleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func (u *UserService) getCakeHandler(w http.ResponseWriter, r *http.Request, user User) {
	w.Write([]byte(user.FavoriteCake))
}

func (u *UserService) getUserInformation(w http.ResponseWriter, r *http.Request, user User) {
	var buf []byte
	userInfo := &UserInformation{
		Email:        user.Email,
		FavoriteCake: user.FavoriteCake,
		Role:         user.Role,
	}
	buf, err := json.Marshal(userInfo)

	if err != nil {
		handleError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *JWTService) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}
	token, err := jwtService.GenearateJWT(user)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

func (u *UserService) updateCake(w http.ResponseWriter, r *http.Request, user User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	cake := string(res)

	err = u.validateCake(cake)
	if err != nil {
		handleError(err, w)
		return
	}
	newUser := User{
		Email:          user.Email,
		PasswordDigest: user.PasswordDigest,
		FavoriteCake:   cake,
		Role:           user.Role,
	}

	err = u.repository.Update(user.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Success."))
}

func (u *UserService) updateEmail(w http.ResponseWriter, r *http.Request, user User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	email := string(res)

	err = u.validateEmail(email)
	if err != nil {
		handleError(err, w)
		return
	}
	newUser := User{
		Email:          email,
		PasswordDigest: user.PasswordDigest,
		FavoriteCake:   user.FavoriteCake,
		Role:           user.Role,
	}

	err = u.repository.Update(user.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Success."))
}

func (u *UserService) updatePassword(w http.ResponseWriter, r *http.Request, user User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	passwordDigest := md5.New().Sum([]byte(string(res)))
	password := string(passwordDigest)

	err = u.validatePass(password)
	if err != nil {
		handleError(err, w)
		return
	}
	newUser := User{
		Email:          user.Email,
		PasswordDigest: password,
		FavoriteCake:   user.FavoriteCake,
		Role:           user.Role,
	}

	err = u.repository.Update(user.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Success."))
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := u.validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
		Role:           "user",
	}
	err = u.repository.Add(params.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))
}
