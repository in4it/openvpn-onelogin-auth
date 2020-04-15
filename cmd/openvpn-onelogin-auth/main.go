package main

import (
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/in4it/openvpn-onelogin-auth/pkg/onelogin"
	"github.com/juju/loggo"
)

func readConfig() onelogin.Config {
	var configfile string
	if os.Getenv("CONFIGFILE") == "" {
		configfile = "/etc/openvpn/onelogin.conf"
	} else {
		configfile = os.Getenv("CONFIGFILE")
	}
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

func main() {
	var (
		success bool
		err     error
	)

	logger := loggo.GetLogger("openvpn-onelogin-auth")
	loggo.ConfigureLoggers(`<root>=INFO`)

	o := onelogin.New(readConfig())

	httpClient := &http.Client{}

	accessToken, _, err := o.GenerateToken(httpClient)
	if err != nil {
		logger.Errorf("Error while generating token: %s\n", err)
		os.Exit(1)
	}

	if o.IsMFAEnabled() {
		success, err = o.CreateSessionLoginTokenWithMFA(httpClient, accessToken, onelogin.SessionLoginTokenParams{
			UsernameOrEmail: os.Getenv("username"),
			Password:        os.Getenv("password"),
		})
	} else {
		success, err = o.CreateSessionLoginToken(httpClient, accessToken, onelogin.SessionLoginTokenParams{
			UsernameOrEmail: os.Getenv("username"),
			Password:        os.Getenv("password"),
		})
	}
	if err != nil {
		logger.Errorf("Authentication failed for user: %s\n", err)
		os.Exit(1)
	}
	if success {
		logger.Infof("Authentication successful for user %s", os.Getenv("username"))
		os.Exit(0)
	} else {
		logger.Infof("Authentication failed for user %s", os.Getenv("username"))
		os.Exit(1)
	}
}
