package onelogin

import "net/http"

type ClientMock struct {
	GetDoFunc   func(req *http.Request) (*http.Response, error)
	VerifyCount int
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	return c.GetDoFunc(req)
}
