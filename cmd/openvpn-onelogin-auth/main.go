package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/in4it/openvpn-onelogin-auth/pkg/onelogin"
	"github.com/juju/loggo"
)

func readConfig() onelogin.Config {
	var configfile = "onelogin.conf"
	_, err := os.Stat(configfile)
	if err != nil {
		log.Fatal("Config file is missing: ", configfile)
	}

	var config onelogin.Config
	if _, err := toml.DecodeFile(configfile, &config); err != nil {
		log.Fatal(err)
	}

	return config
}

func getPasswordAndToken() (string, string, error) {
	password := os.Getenv("password")
	if len(password) < 7 {
		return "", "", fmt.Errorf("No OTP Supplied")
	}
	return password[0 : len(password)-6], password[len(password)-6:], nil
}

func main() {
	var err error

	logger := loggo.GetLogger("openvpn-onelogin-auth")
	loggo.ConfigureLoggers(`<root>=INFO`)

	o := onelogin.New(readConfig())

	password, passwordToken, err := getPasswordAndToken()
	if err != nil {
		logger.Infof("Authentication failed: no password/otp supplied")
		os.Exit(1)
	}

	token, err := o.GenerateToken()
	if err != nil {
		logger.Errorf("Error while generating token: %s\n", err)
		os.Exit(1)
	}
	if len(token.Data) == 0 {
		logger.Errorf("No token returned\n")
		os.Exit(1)
	}
	session, err := o.CreateSessionLoginTokenWithMFA(token.Data[0].AccessToken, onelogin.SessionLoginTokenParams{
		UsernameOrEmail: os.Getenv("username"),
		Password:        password,
	})

	if err != nil {
		logger.Errorf("Error while creating session: %s\n", err)
		os.Exit(1)
	}

	if session.Status.Code == 200 && session.Status.Message == "MFA is required for this user" {
		if len(session.Data) == 0 {
			logger.Errorf("No data returned\n")
		}
		if len(session.Data[0].Devices) == 0 {
			logger.Errorf("No MFA devices returned\n")
		}

		session, err = o.VerifyFactor(token.Data[0].AccessToken, onelogin.VerifyFactorParams{
			DeviceID:   strconv.FormatInt(session.Data[0].Devices[0].DeviceID, 10),
			StateToken: session.Data[0].StateToken,
			OptToken:   passwordToken,
		})
		if err != nil {
			logger.Errorf("Error while creating session during VerifyFactor: %s\n", err)
			os.Exit(1)
		}
	}

	if session.Status.Code == 200 && session.Status.Message == "Success" {
		logger.Infof("Authentication successful for user %s", os.Getenv("username"))
		os.Exit(0)
	} else {
		logger.Infof("Authentication failed for user %s (%d: %s)", os.Getenv("username"), session.Status.Code, session.Status.Message)
		os.Exit(1)
	}
}
