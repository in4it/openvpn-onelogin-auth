package onelogin

import (
	"bytes"
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

	tokenResponse, err := o.GenerateToken(client)
	if err != nil {
		t.Errorf("GenerateToken error: %s", err)
		return
	}
	if tokenResponse.Data[0].AccessToken != "xx508xx63817x752xx74004x30705xx92x58349x5x78f5xx34xxxxx51" {
		t.Errorf("Got wrong access token: %s", tokenResponse.Data[0].AccessToken)
		return
	}
	if tokenResponse.Data[0].RefreshToken != "628x9x0xx447xx4x421x517x4x474x33x2065x4x1xx523xxxxx6x7x20" {
		t.Errorf("Got wrong refresh token: %s", tokenResponse.Data[0].RefreshToken)
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

	session, err := o.CreateSessionLoginTokenWithMFA(client, "token", SessionLoginTokenParams{
		UsernameOrEmail: "username",
		Password:        "password",
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
