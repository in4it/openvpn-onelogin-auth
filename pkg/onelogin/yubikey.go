package onelogin

import (
	"regexp"
)

func hasYubiKeyToken(input string) (bool, string) {
	if len(input) < 44 {
		return false, ""
	}
	matched, _ := regexp.Match(`[cbdefghijklnrtuv]{44}$`, []byte(input))
	if matched {
		return true, input[len(input)-44:]
	}
	return matched, ""
}
