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
		return errors.New("Password`s length must be more than 8 symbols.")
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
	if (admin.Role != "admin" && admin.Role != "superadmin") || (user.Role == admin.Role || user.Role == "superadmin") {
		return false
	}
	return true
}

func (u *UserService) getBanReason(email string) (string, error) {
	history, err := u.banHistoryRepository.GetHistory(email)
	if err != nil {
		return "", err
	}
	events := strings.Split(history, "\n")
	if len(events) == 0 {
		return "", nil
	}
	splited := strings.Split(events[len(events)-1], "Reason:")
	if len(splited) != 2 {
		return "", errors.New("User is not baned.")
	}
	return strings.TrimSpace(splited[len(splited)-1]), nil
}
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
	userToBan, findErr := u.repository.Get(params.Email)
	if findErr != nil {
		handleError(findErr, w)
		return
	}

	_, banerr := u.getBanReason(params.Email)
	if banerr == nil {
		handleError(errors.New("User is already banned."), w)
		return
	}
	if u.hasEnoughRights(user, userToBan) == false {
		w.WriteHeader(401)
		w.Write([]byte("Access denied."))
		return
	}

	event := "Ban by " + user.Email + ". Reason:" + params.Reason
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
	userToUnban, findErr := u.repository.Get(email)
	if findErr != nil {
		handleError(findErr, w)
		return
	}
	if u.hasEnoughRights(user, userToUnban) == false {
		w.WriteHeader(401)
		w.Write([]byte("Access denied."))
		return
	}
	_, unbanerr := u.getBanReason(email)
	if unbanerr != nil {
		handleError(unbanerr, w)
		return
	}

	event := "Unbaned by " + user.Email + " at " + strconv.FormatInt(time.Now().Unix(), 10)
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
	if u.hasEnoughRights(user, userToInspect) == false {
		w.WriteHeader(401)
		w.Write([]byte("Access denied."))
		return
	}
	history, historyErr := u.banHistoryRepository.GetHistory(userToInspect.Email)
	if historyErr != nil {
		handleError(findErr, w)
		return
	}

	inspectInfo := &InspectInfo{
		Email:        userToInspect.Email,
		FavoriteCake: userToInspect.FavoriteCake,
		Role:         userToInspect.Role,
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

func getCakeHandler(w http.ResponseWriter, r *http.Request, user User) {
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
	usr, _ := u.repository.Get(email)
	if len(usr.Email) != 0 {
		handleError(errors.New("user with this email already exists."), w)
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
func (u *UserService) promote(w http.ResponseWriter, r *http.Request, user User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(err, w)
		return
	}
	email := string(res)
	if err := u.validateEmail(email); err != nil {
		handleError(err, w)
		return
	}
	if user.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Access denied."))
		return
	}
	userToPromote, err := u.repository.Get(email)
	if err != nil {
		handleError(err, w)
		return
	}
	if userToPromote.Role != "user" {
		handleError(errors.New("User is already promoted."), w)
		return
	}

	updated := User{
		Email:          userToPromote.Email,
		PasswordDigest: userToPromote.PasswordDigest,
		FavoriteCake:   userToPromote.FavoriteCake,
		Role:           "admin",
	}
	err = u.repository.Update(userToPromote.Email, updated)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Success."))
}

func (u *UserService) fire(w http.ResponseWriter, r *http.Request, admin User) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(err, w)
		return
	}
	email := string(res)
	if err := u.validateEmail(email); err != nil {
		handleError(err, w)
		return
	}
	if admin.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("Access denied."))
		return
	}
	userToFire, err := u.repository.Get(email)
	if err != nil {
		handleError(err, w)
		return
	}
	if userToFire.Role == "user" {
		handleError(errors.New("User is not admin."), w)
		return
	}

	updated := User{
		Email:          userToFire.Email,
		PasswordDigest: userToFire.PasswordDigest,
		FavoriteCake:   userToFire.FavoriteCake,
		Role:           "user",
	}
	err = u.repository.Update(userToFire.Email, updated)
	if err != nil {
		handleError(err, w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Success."))
}
