package onelogin

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestGenerateToken(t *testing.T) {

	o := New(Config{
		Subdomain:    "test.com",
		URL:          "https://www.test.com",
		ClientID:     "clientid",
		ClientSecret: "secret",
	})

	client := &ClientMock{}
	client.GetDoFunc = func(req *http.Request) (*http.Response, error) {
		// example from https://developers.onelogin.com/api-docs/1/oauth20-tokens/generate-tokens
		json := `{
			"status": {
				"error": false,
				"code": 200,
				"type": "success",
				"message": "Success"
			},
			"data": [
				{
					"access_token": "xx508xx63817x752xx74004x30705xx92x58349x5x78f5xx34xxxxx51",
					"created_at": "2015-11-11T03:36:18.714Z",
					"expires_in": 36000,
					"refresh_token": "628x9x0xx447xx4x421x517x4x474x33x2065x4x1xx523xxxxx6x7x20",
					"token_type": "bearer",
					"account_id": 555555
				}
		 ]
		}`
		r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

		if req.Header.Get("Authorization") != "client_id:"+o.config.ClientID+", client_secret:"+o.config.ClientSecret {
			return &http.Response{
				StatusCode: 401,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			}, nil
		}

		return &http.Response{
			StatusCode: 200,
			Body:       r,
		}, nil
	}

	accessToken, refreshToken, err := o.GenerateToken(client)
	if err != nil {
		t.Errorf("GenerateToken error: %s", err)
		return
	}
	if accessToken != "xx508xx63817x752xx74004x30705xx92x58349x5x78f5xx34xxxxx51" {
		t.Errorf("Got wrong access token: %s", accessToken)
		return
	}
	if refreshToken != "628x9x0xx447xx4x421x517x4x474x33x2065x4x1xx523xxxxx6x7x20" {
		t.Errorf("Got wrong refresh token: %s", refreshToken)
		return
	}

}
func TestCreateSessionLoginToken(t *testing.T) {
	o := New(Config{
		Subdomain:    "test.com",
		URL:          "https://www.test.com",
		ClientID:     "clientid",
		ClientSecret: "secret",
	})

	bearerToken := "abc"

	client := &ClientMock{}
	client.GetDoFunc = func(req *http.Request) (*http.Response, error) {
		// example from https://developers.onelogin.com/api-docs/1/login-page/create-session-login-token
		json := `{
			"status": {
				"type": "success",
				"message": "Success",
				"code": 200,
				"error": false
			},
			"data": [
				{
					"status": "Authenticated",
					"user": {
						"username": "kinua",
						"email": "kinua.wong@company.com",
						"firstname": "Kinua",
						"id": 88888888,
						"lastname": "Wong"
					},
					"return_to_url": null,
					"expires_at": "2016/01/07 05:56:21 +0000",
					"session_token": "9x8869x31134x7906x6x54474x21x18xxx90857x"
				}
			]
		}`
		r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

		if req.Header.Get("Authorization") == "bearer: "+bearerToken {
			return &http.Response{
				StatusCode: 401,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			}, nil
		}

		return &http.Response{
			StatusCode: 200,
			Body:       r,
		}, nil
	}

	success, err := o.CreateSessionLoginToken(client, "token", SessionLoginTokenParams{
		UsernameOrEmail: "username",
		Password:        "password",
	})
	if err != nil {
		t.Errorf("CreateSessionLoginTokenWithMFA error: %s", err)
		return
	}
	if !success {
		t.Errorf("CreateSessionLoginTokenWithMFA didn't respond with 200")
		return
	}
}

func TestCreateSessionLoginTokenWithMFA(t *testing.T) {
	o := New(Config{
		Subdomain:    "test.com",
		URL:          "https://www.test.com",
		ClientID:     "clientid",
		ClientSecret: "secret",
	})

	bearerToken := "abc"

	client := &ClientMock{}
	client.GetDoFunc = func(req *http.Request) (*http.Response, error) {
		// example from https://developers.onelogin.com/api-docs/1/login-page/create-session-login-token
		jsonResponse := ""
		errorResponse := &http.Response{
			StatusCode: 400,
			Body: ioutil.NopCloser(bytes.NewReader([]byte(`{
				"status": {
					"code": 400,
					"error": true,
					"message": "Input JSON is not valid",
					"type": "bad request"
				}
			}
			`))),
		}
		if req.Header.Get("Authorization") == "bearer: "+bearerToken {
			return &http.Response{
				StatusCode: 401,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			}, nil
		}
		if req.URL.Path == "/api/1/login/auth" {
			jsonResponse = `{
				"status": {
					"type": "success",
					"code": 200,
					"message": "MFA is required for this user",
					"error": false
				},
				"data": [
					{
						"user": {
							"email": "jennifer.hasenfus@onelogin.com",
							"username": "jhasenfus",
							"firstname": "Jennifer",
							"lastname": "Hasenfus",
							"id": 88888888
						},
						"state_token": "xf4330878444597bd3933d4247cc1xxxxxxxxxxx",
						"callback_url": "https://api.us.onelogin.com/api/1/login/verify_factor",
						"devices": [
							{
								"device_type": "Google Authenticator",
								"device_id": 444444
							},
							{
								"device_type": "OneLogin Protect",
								"device_id": 111111
							},
							{
								"device_type": "Yubico YubiKey",
								"device_id": 555555
							}
						]
					}
				]
			}`
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(jsonResponse))),
			}, nil
		}
		if req.URL.Path == "/api/1/login/verify_factor" {
			defer req.Body.Close()
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return errorResponse, err
			}
			var params VerifyFactorParams

			err = json.Unmarshal(body, &params)
			if err != nil {
				return errorResponse, err
			}

			if params.DeviceID != "444444" {
				return &http.Response{
					StatusCode: 400,
					Body: ioutil.NopCloser(bytes.NewReader([]byte(`{
						"status": {
							"code": 400,
							"error": true,
							"message": "Test failed: device id is not expected id",
							"type": "bad request"
						}
					}
					`))),
				}, nil
			}

			jsonResponse = `{
				"status": {
					"type": "success",
					"message": "Success",
					"code": 200,
					"error": false
				},
				"data": [
					{
						"status": "Authenticated",
						"user": {
							"username": "kinua",
							"email": "kinua.wong@company.com",
							"firstname": "Kinua",
							"id": 88888888,
							"lastname": "Wong"
						},
						"return_to_url": null,
						"expires_at": "2016/01/07 05:56:21 +0000",
						"session_token": "9x8869x31134x7906x6x54474x21x18xxx90857x"
					}
				]
			}`
			return &http.Response{
				StatusCode: 200,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(jsonResponse))),
			}, nil
		}
		// no match on URI
		return errorResponse, nil
	}

	inputUsername := "username"
	inputPassword := "password123456"

	success, err := o.CreateSessionLoginTokenWithMFA(client, "token", SessionLoginTokenParams{
		UsernameOrEmail: inputUsername,
		Password:        inputPassword,
	})
	if err != nil {
		t.Errorf("CreateSessionLoginTokenWithMFA error: %s", err)
		return
	}
	if !success {
		t.Errorf("CreateSessionLoginTokenWithMFA didn't respond with 200")
		return
	}
}

func TestMFA(t *testing.T) {

	o := New(Config{
		Subdomain:    "test.com",
		URL:          "https://www.test.com",
		ClientID:     "clientid",
		ClientSecret: "secret",
	})
	devices := []SessionResponseDevices{
		{
			DeviceType: "OneLogin OTP SMS",
			DeviceID:   111111,
		},
		{
			DeviceType: "Google Authenticator",
			DeviceID:   444444,
		},
		{
			DeviceType: "Yubico YubiKey",
			DeviceID:   555555,
		},
	}

	inputPassword := "password123456"
	inputPasswordYubikey := "passwordcccjgjgkhcbbirdrfdnlnghhfgrtnnlgedjlftrbdeut"

	// test with google auth
	password, passwordToken, passwordTokenType, err := o.GetPasswordAndToken(inputPassword)
	if err != nil {
		t.Errorf("CreateSessionLoginTokenWithMFA error: %s", err)
		return
	}
	if password != inputPassword[:len(inputPassword)-6] {
		t.Errorf("CreateSessionLoginTokenWithMFA error: password mismatch: %s vs %s", password, inputPassword[:len(inputPassword)-6])
		return
	}

	if passwordToken != "123456" {
		t.Errorf("CreateSessionLoginTokenWithMFA error: token mismatch")
		return
	}
	if deviceID, err := o.GetDeviceIDByTokenType(devices, passwordTokenType); err != nil || deviceID != "444444" {
		t.Errorf("CreateSessionLoginTokenWithMFA error: GetDeviceIDByTokenType: %s (deviceId: %s)", err, deviceID)
		return
	}

	// test with yubikey
	password, passwordToken, passwordTokenType, err = o.GetPasswordAndToken(inputPasswordYubikey)
	if err != nil {
		t.Errorf("CreateSessionLoginTokenWithMFA error: %s", err)
		return
	}
	if password != inputPassword[:len(inputPasswordYubikey)-44] {
		t.Errorf("CreateSessionLoginTokenWithMFA error: password mismatch: %s vs %s", password, inputPassword[:len(inputPasswordYubikey)-44])
		return
	}

	if passwordToken != inputPasswordYubikey[len(inputPasswordYubikey)-44:] {
		t.Errorf("CreateSessionLoginTokenWithMFA error: token mismatch: %s vs %s", passwordToken, inputPasswordYubikey[len(inputPasswordYubikey)-44:])
		return
	}
	if deviceID, err := o.GetDeviceIDByTokenType(devices, passwordTokenType); err != nil || deviceID != "555555" {
		t.Errorf("CreateSessionLoginTokenWithMFA error: GetDeviceIDByTokenType: %s (deviceId: %s)", err, deviceID)
		return
	}
}

func TestVerifyFactor(t *testing.T) {
	o := New(Config{
		Subdomain:    "test.com",
		URL:          "https://www.test.com",
		ClientID:     "clientid",
		ClientSecret: "secret",
	})

	bearerToken := "abc"

	client := &ClientMock{}
	client.GetDoFunc = func(req *http.Request) (*http.Response, error) {
		// example from https://developers.onelogin.com/api-docs/1/login-page/verify-factor
		json := `{
			"status": {
				"type": "success",
				"code": 200,
				"message": "Success",
				"error": false
			},
			"data": [
				{
					"return_to_url": null,
					"user": {
						"username": "jhasenfus",
						"email": "jennifer.hasenfus@onelogin.com",
						"firstname": "Jennifer",
						"lastname": "Hasegawa",
						"id": 88888888
					},
					"status": "Authenticated",
					"session_token": "xxxxxxxxx8a4c07773a5454f946",
					"expires_at": "2016/01/26 02:21:47 +0000"
				}
			]
		}`
		r := ioutil.NopCloser(bytes.NewReader([]byte(json)))

		if req.Header.Get("Authorization") == "bearer: "+bearerToken {
			return &http.Response{
				StatusCode: 401,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
			}, nil
		}

		return &http.Response{
			StatusCode: 200,
			Body:       r,
		}, nil
	}

	session, err := o.VerifyFactor(client, "token", VerifyFactorParams{
		DeviceID:   "1",
		StateToken: "stateToken",
		OptToken:   "123456",
	})
	if err != nil {
		t.Errorf("CreateSessionLoginTokenWithMFA error: %s", err)
		return
	}
	if session.Status.Code != 200 || session.Status.Message != "Success" {
		t.Errorf("CreateSessionLoginTokenWithMFA didn't respond with 200: %d", session.Status.Code)
		return
	}
}
