package onelogin

import (
	"testing"
)

func TestIsToken(t *testing.T) {
	token := "123456"
	if !isToken(token) {
		t.Errorf("Not a token")
	}
	token = ""
	if isToken(token) {
		t.Errorf("Not a token (token is empty string)")
	}
}

func TestHasToken(t *testing.T) {
	passwords := []string{"a123456", "abc999999"}
	for _, password := range passwords {
		if _, _, res := hasToken(password); !res {
			t.Errorf("Identified as has no token: %s", password)
		}
	}
	password := "123"
	if _, _, res := hasToken(password); res {
		t.Errorf("Identified as has a token: %s", password)
	}
	password = "zzzzzzzzz123"
	if _, _, res := hasToken(password); res {
		t.Errorf("Identified as has a token: %s", password)
	}
	password = "abc123456"
	pass, token, res := hasToken(password)
	if !(res && pass == "abc" && token == "123456") {
		t.Errorf("Identified as has no token: %s (pass: %s, token: %s)", password, pass, token)
	}
}
