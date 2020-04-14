package onelogin

import (
	"testing"
)

func TestIsYubikeyToken(t *testing.T) {
	var (
		retToken string
		hasToken bool
	)
	passwd := "mypasszz"
	tokens := []string{
		"vvddbuvjvkbhrtkjrdhvlenirbebujtuhfkrnkvbflcr",
		"444jgjgkhcbbirdrfdnlnghhfgrtnnlgedjlftrbdeuz",
	}
	if hasToken, retToken = hasYubiKeyToken(passwd + tokens[0]); !hasToken {
		t.Errorf("valid yubikey: verifyYubiKeyToken returns is not valid")
		return
	}
	if retToken != tokens[0] {
		t.Errorf("valid yubikey: returned token is not equal to input token")
		return
	}

	if hasToken, _ = hasYubiKeyToken(tokens[1]); hasToken {
		t.Errorf("invalid yubikey: verifyYubiKeyToken returns is valid")
		return
	}
}
