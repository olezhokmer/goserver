package main

type User struct {
	Email          string
	PasswordDigest string
	Role           string
	FavoriteCake   string
}
type UserInformation struct {
	Email        string
	Role         string
	FavoriteCake string
}
type UserRegisterParams struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}
type InspectInfo struct {
	Email        string
	Role         string
	FavoriteCake string
	History      string
}
