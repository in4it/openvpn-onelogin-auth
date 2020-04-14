package onelogin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/juju/loggo"
)

var logger = loggo.GetLogger("onelogin.authenticate")

type VerifyFactorParams struct {
	DeviceID    string `json:"device_id"`
	StateToken  string `json:"state_token"`
	OptToken    string `json:"otp_token,omitempty"`
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

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func (o *onelogin) GenerateToken(client HttpClient) (TokenResponse, error) {
	var tokenResponse TokenResponse
	auth := "client_id:" + o.config.ClientID + ", client_secret:" + o.config.ClientSecret
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
func (o *onelogin) CreateSessionLoginToken(client HttpClient, token string, params SessionLoginTokenParams) (bool, error) {
	var sessionResponse SessionResponse

	params.Subdomain = o.config.Subdomain
	b, err := json.Marshal(params)
	if err != nil {
		return false, err
	}
	buf := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", o.config.URL+"/api/1/login/auth", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "bearer:"+token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	if resp.StatusCode == 400 {
		return false, fmt.Errorf("Statuscode 400 (bad request)")
	}

	err = json.Unmarshal(body, &sessionResponse)

	if err != nil {
		return false, err
	}

	if sessionResponse.Status.Code == 200 && sessionResponse.Status.Message == "MFA is required for this user" {
		return false, nil
	}

	if sessionResponse.Status.Code == 200 && sessionResponse.Status.Message == "Success" {
		return true, nil
	}

	return false, fmt.Errorf("Authentication failed: %d - %s", sessionResponse.Status.Code, sessionResponse.Status.Message)
}

func (o *onelogin) CreateSessionLoginTokenWithMFA(client HttpClient, token string, params SessionLoginTokenParams) (bool, error) {
	var sessionResponse SessionResponse

	password, passwordToken, passwordTokenType, err := o.GetPasswordAndToken(params.Password)
	if err != nil {
		return false, fmt.Errorf("Authentication failed: no password/otp supplied")
	}
	params.Password = password

	params.Subdomain = o.config.Subdomain
	b, err := json.Marshal(params)
	if err != nil {
		return false, err
	}
	buf := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", o.config.URL+"/api/1/login/auth", buf)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "bearer:"+token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	if resp.StatusCode == 400 {
		return false, fmt.Errorf("Statuscode 400 (bad request)")
	}

	err = json.Unmarshal(body, &sessionResponse)

	if err != nil {
		return false, err
	}

	if sessionResponse.Status.Code == 200 && sessionResponse.Status.Message == "Success" {
		// no MFA required
		return false, fmt.Errorf("MFA is enabled, but user doesn't have MFA setup")
	}
	if len(sessionResponse.Data) == 0 {
		return false, fmt.Errorf("No data returned\n")
	}
	if len(sessionResponse.Data[0].Devices) == 0 {
		return false, fmt.Errorf("No MFA devices returned\n")
	}

	deviceID, err := o.GetDeviceIDByTokenType(sessionResponse.Data[0].Devices, passwordTokenType)
	if err != nil {
		return false, fmt.Errorf("function GetDeviceIdByTokenType error: %s", err)
	}

	verifyFactorResponse, err := o.VerifyFactor(client, token, VerifyFactorParams{
		DeviceID:   deviceID,
		StateToken: sessionResponse.Data[0].StateToken,
		OptToken:   passwordToken,
	})
	if err != nil {
		return false, fmt.Errorf("function Error while creating session during VerifyFactor: %s", err)
	}

	if verifyFactorResponse.Status.Code == 200 && verifyFactorResponse.Status.Message == "Success" {
		// MFA auth succeeded
		return true, nil
	}
	return false, fmt.Errorf("Authentication failed: %d - %s", verifyFactorResponse.Status.Code, verifyFactorResponse.Status.Message)
}

func (o *onelogin) VerifyFactor(client HttpClient, token string, params VerifyFactorParams) (SessionResponse, error) {
	var sessionResponse SessionResponse

	b, err := json.Marshal(params)
	if err != nil {
		return sessionResponse, err
	}
	buf := bytes.NewBuffer(b)
	req, err := http.NewRequest("POST", o.config.URL+"/api/1/login/verify_factor", buf)
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

	err = json.Unmarshal(body, &sessionResponse)

	if err != nil {
		return sessionResponse, err
	}

	return sessionResponse, nil
}

func (o *onelogin) IsMFAEnabled() bool {
	if o.config.MFA == true {
		return true
	}
	return false
}

func (o *onelogin) GetPasswordAndToken(password string) (string, string, string, error) {
	// does it have a yubikey token
	if hasToken, retToken := hasYubiKeyToken(password); hasToken {
		return password[:len(password)-len(retToken)], retToken, "Yubico YubiKey", nil
	}
	if len(password) < 7 {
		return "", "", "", fmt.Errorf("No OTP Supplied")
	}
	return password[0 : len(password)-6], password[len(password)-6:], "Google Authenticator", nil
}

func (o *onelogin) GetDeviceIDByTokenType(input []SessionResponseDevices, tokenType string) (string, error) {
	for _, v := range input {
		if v.DeviceType == tokenType {
			return strconv.FormatInt(v.DeviceID, 10), nil
		}
	}
	return "", fmt.Errorf("couldn't find device type '%s' in onelogin's enrolled devices for this user", tokenType)
}
