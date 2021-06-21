package onelogin

import (
	"regexp"
)

func isToken(str string) bool {
	var tokenCheck = regexp.MustCompile(`^[0-9]+$`)
	return tokenCheck.MatchString(str)
}

func hasToken(str string) (string, string, bool) {
	if len(str) < 6 {
		return str, "", false
	}
	if isToken(str[len(str)-6:]) {
		return str[0 : len(str)-6], str[len(str)-6:], true
	}
	return str, "", false
}
