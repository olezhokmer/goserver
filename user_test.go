package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		resp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		return parsedResponse{res.StatusCode, resp}
	}
}
func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}
func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
		banHistoryRepository: NewInMemoryBanHistoryStorage(),
	}
}
func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d, actual: %d", expected, r.status)
	}
}
func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s, actual: %s", expected, actual)
	}
}

func TestUsers_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("test unauthorized", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, getCakeHandler)))
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.FailNow()
		}
		res := doRequest(req, nil)
		assertStatus(t, 401, res)
		assertBody(t, "unauthorized", res)
	})
	t.Run("user does not exist", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("wrong password", func(t *testing.T) {
		t.Skip()
	})

	t.Run("invalid password", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "email@gmail.com",
			"favorite_cake": "abc",
			"password":      "1234567",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Password`s length must be more than 8 symbols.", resp)
	})

	t.Run("invalid email", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "fgrt5g65g6",
			"favorite_cake": "abc",
			"password":      "123456",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Invalid email.", resp)
	})

	t.Run("invalid cake", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "1@gmail.com",
			"favorite_cake": "addcr12cf4",
			"password":      "12345678",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Cake must contain only latters.", resp)
	})

	t.Run("empty cake", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "1@gmail.com",
			"favorite_cake": "",
			"password":      "12345678",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Empty cake.", resp)
	})

	t.Run("register", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "1@gmail.com",
			"favorite_cake": "abc",
			"password":      "12345678",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("user exists", func(t *testing.T) {
		u := newTestUserService()
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "1@gmail.com",
			"favorite_cake": "abc",
			"password":      "12345678",
		}
		ts.Client().Post(ts.URL+"/user/regiser", "", prepareParams(t, params))
		res, err := ts.Client().Post(ts.URL, "", prepareParams(t, params))
		if err != nil {
			return
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return
		}
		pres := parsedResponse{res.StatusCode, body}
		assertStatus(t, 422, pres)
		assertBody(t, "User exists.", pres)
	})

	t.Run("login jwt", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		res := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		assertStatus(t, 200, res)
	})

	t.Run("get cake", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, getCakeHandler)))

		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "abc", resp)
	})

	t.Run("update cake", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		res := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(res.body)
		bearer := "Bearer " + jwt

		cake := "abcd"
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.updateCake)))

		req, err := http.NewRequest("PUT", ts.URL, bytes.NewBuffer([]byte(cake)))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		doRequest(req, nil)

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, getCakeHandler)))

		req, err = http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		res = doRequest(req, nil)

		assertStatus(t, 200, res)
		assertBody(t, cake, res)
	})

	t.Run("update email", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		email := "2@gmail.com"
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.updateEmail)))

		req, err := http.NewRequest("PUT", ts.URL, bytes.NewBuffer([]byte(email)))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		doRequest(req, nil)

		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp = doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "2@gmail.com",
				"password": "12345678",
			},
		)))

		assertStatus(t, 200, resp)
	})

	t.Run("update password", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		pass := "123456789"
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.updatePassword)))

		req, err := http.NewRequest("PUT", ts.URL, bytes.NewBuffer([]byte(pass)))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		doRequest(req, nil)

		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		resp = doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": pass,
			},
		)))
		assertStatus(t, 200, resp)
	})

	t.Run("user info", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "1@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.getUserInformation)))

		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
	})
}
func Test_admin_system(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("promote default user", func(t *testing.T) {
		u := newTestUserService()
		u.createSuperAdmin()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "superadmin@gmail.com",
				"password": "12345678",
			},
		)))
		
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.promote)))
		req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("1@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 201, resp)
		assertBody(t, "Success.", resp)
	})
	t.Run("promote admin", func(t *testing.T) {
		u := newTestUserService()
		u.createSuperAdmin()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "superadmin@gmail.com",
				"password": "12345678",
			},
		)))
		
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.promote)))
		req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("superadmin@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "User is already promoted.", resp)
	})
	
	t.Run("fire default user", func(t *testing.T) {
		u := newTestUserService()
		u.createSuperAdmin()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "superadmin@gmail.com",
				"password": "12345678",
			},
		)))
		
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.fire)))
		req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("1@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "User is not admin.", resp)
	})
	t.Run("fire admin", func(t *testing.T) {
		u := newTestUserService()
		u.createSuperAdmin()
		u.createAdmin()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "superadmin@gmail.com",
				"password": "12345678",
			},
		)))
		
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.fire)))
		req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("admin@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 201, resp)
		assertBody(t, "Success.", resp)
	})

	t.Run("unban unbanned user", func(t *testing.T) {
		u := newTestUserService()
		u.createAdmin()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))
		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "admin@gmail.com",
				"password": "12345678",
			},
		)))
		
		jwt := string(resp.body)
		bearer := "Bearer " + jwt

		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.unban)))
		req, err := http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("1@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)
		resp = doRequest(req, nil)

		assertStatus(t, 422, resp)
		assertBody(t, "User is not baned.", resp)
	})
	t.Run("ban user", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		u.createAdmin()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))

		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "admin@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.ban)))
		defer ts.Close()
		p := map[string]interface{}{
			"email":  "1@gmail.com",
			"reason": "bad user",
		}
		req, err := http.NewRequest("POST", ts.URL, prepareParams(t, p))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)

		assertStatus(t, 200, resp)
		assertBody(t, "Success.", resp)
	})
	t.Run("ban admin", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		u.createAdmin()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()


		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "admin@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.ban)))
		defer ts.Close()
		p := map[string]interface{}{
			"email":  "admin@gmail.com",
			"reason": "bad user",
		}
		req, err := http.NewRequest("POST", ts.URL, prepareParams(t, p))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)

		assertStatus(t, 401, resp)
		assertBody(t, "Access denied.", resp)
	})
	t.Run("ban banned user", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		u.createAdmin()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))

		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "admin@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.ban)))
		defer ts.Close()
		p := map[string]interface{}{
			"email":  "1@gmail.com",
			"reason": "bad user",
		}
		req, err := http.NewRequest("POST", ts.URL, prepareParams(t, p))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)

		req, err = http.NewRequest("POST", ts.URL, prepareParams(t, p))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)
		assertStatus(t, 422, resp)
		assertBody(t, "User is already banned.", resp)
	})
	t.Run("unban banned user", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		u.createAdmin()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":         "1@gmail.com",
				"favorite_cake": "abc",
				"password":      "12345678",
			},
		)))

		ts = httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, 
			map[string]interface{}{
				"email":    "admin@gmail.com",
				"password": "12345678",
			},
		)))
		jwt := string(resp.body)
		bearer := "Bearer " + jwt
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.ban)))
		defer ts.Close()
		p := map[string]interface{}{
			"email":  "1@gmail.com",
			"reason": "bad user",
		}
		req, err := http.NewRequest("POST", ts.URL, prepareParams(t, p))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)
		ts = httptest.NewServer(http.HandlerFunc(j.jwtAuth(u, u.unban)))
		req, err = http.NewRequest("POST", ts.URL, bytes.NewBuffer([]byte("1@gmail.com")))
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Authorization", bearer)

		resp = doRequest(req, nil)
		assertStatus(t, 200, resp)
		assertBody(t, "Success.", resp)
	})
}