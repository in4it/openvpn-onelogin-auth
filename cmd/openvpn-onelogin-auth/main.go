package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/in4it/openvpn-onelogin-auth/pkg/onelogin"
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

	o := onelogin.New(readConfig())

	password, passwordToken, err := getPasswordAndToken()

	token, err := o.GenerateToken()
	if err != nil {
		fmt.Printf("Error while generating token: %s\n", err)
		return
	}
	if len(token.Data) == 0 {
		fmt.Printf("No token returned\n")
		return
	}
	session, err := o.CreateSessionLoginTokenWithMFA(token.Data[0].AccessToken, onelogin.SessionLoginTokenParams{
		UsernameOrEmail: os.Getenv("username"),
		Password:        password,
	})

	if err != nil {
		fmt.Printf("Error while creating session: %s\n", err)
		return
	}

	if session.Status.Code == 200 && session.Status.Message == "MFA is required for this user" {
		if len(session.Data) == 0 {
			fmt.Printf("No data returned\n")
		}
		if len(session.Data[0].Devices) == 0 {
			fmt.Printf("No MFA devices returned\n")
		}

		o.VerifyFactor(onelogin.VerifyFactorParams{
			DeviceID:   strconv.FormatInt(session.Data[0].Devices[0].DeviceID, 10),
			StateToken: session.Data[0].StateToken,
			OptToken:   passwordToken,
		})
	} else if session.Status.Code == 200 && session.Status.Message == "Success" {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
