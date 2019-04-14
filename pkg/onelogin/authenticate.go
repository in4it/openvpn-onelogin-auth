package onelogin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type VerifyFactorParams struct {
	DeviceID    string `json:"device_id"`
	StateToken  string `json:"state_token"`
	OptToken    string `json:"opt_token,omitempty"`
	DoNotNotify bool   `json:"do_not_notify,omitempty"`
}

type SessionLoginTokenParams struct {
	UsernameOrEmail string `json:"username_or_email"`
	Password        string `json:"password"`
	Subdomain       string `json:"subdomain"`
}
type TokenResponse struct {
	Status TokenResponseStatus `json:"status"`
	Data   []TokenResponseData `json:"data"`
}
type TokenResponseStatus struct {
	Error   bool   `json:"error"`
	Code    int64  `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}
type TokenResponseData struct {
	AccessToken  string `json:"access_token"`
	CreatedAt    string `json:"created_at"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	AccountID    int64  `json:"account_id"`
}

type SessionResponse struct {
	Status SessionResponseStatus `json:"status"`
	Data   []SessionResponseData `json:"data"`
}
type SessionResponseStatus struct {
	Error   bool   `json:"error"`
	Code    int64  `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}
type SessionResponseData struct {
	Status       string                   `json:"status"`
	User         SessionResponseUser      `json:"created_at"`
	ReturnToURL  string                   `json:"return_to_url"`
	ExpiresAt    string                   `json:"expires_at"`
	SessionToken string                   `json:"session_token"`
	StateToken   string                   `json:"state_token"`
	CallbackURL  string                   `json:"callback_url"`
	Devices      []SessionResponseDevices `json:"devices"`
}
type SessionResponseDevices struct {
	DeviceType string `json:"device_type"`
	DeviceID   int64  `json:"device_id"`
}
type SessionResponseUser struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Firstname string `json:"firstname"`
	ID        int64  `json:"id"`
	Lastname  string `json:"lastname"`
}

func (o *onelogin) GenerateToken() (TokenResponse, error) {
	var tokenResponse TokenResponse
	auth := "client_id:" + o.config.ClientID + ", client_secret:" + o.config.ClientSecret
	client := &http.Client{}
	buf := bytes.NewBuffer([]byte(`{"grant_type": "client_credentials"}`))
	req, err := http.NewRequest("POST", o.config.URL+"/auth/oauth2/token", buf)
	if err != nil {
		return tokenResponse, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse, err
	}

	if resp.StatusCode != 200 {
		return tokenResponse, fmt.Errorf("Statuscode was not 200 (is %d)", resp.StatusCode)
	}

	err = json.Unmarshal(body, &tokenResponse)

	return tokenResponse, err
}
func (o *onelogin) CreateSessionLoginTokenWithMFA(token string, params SessionLoginTokenParams) (SessionResponse, error) {
	var sessionResponse SessionResponse
	client := &http.Client{}

	params.Subdomain = o.config.Subdomain
	b, err := json.Marshal(params)
	if err != nil {
		return sessionResponse, err
	}
	buf := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", o.config.URL+"/api/1/login/auth", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "bearer:"+token)
	resp, err := client.Do(req)
	if err != nil {
		return sessionResponse, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return sessionResponse, err
	}

	if resp.StatusCode == 400 {
		return sessionResponse, fmt.Errorf("Statuscode 400 (bad request)")
	}

	fmt.Printf("body: %s\n", string(body))

	err = json.Unmarshal(body, &sessionResponse)

	if err != nil {
		return sessionResponse, err
	}

	return sessionResponse, nil
}

func (o *onelogin) VerifyFactor(params VerifyFactorParams) {

}
