package onelogin

type Config struct {
	Subdomain    string `toml:"ONELOGIN_SUBDOMAIN"`
	URL          string `toml:"ONELOGIN_URL"`
	ClientID     string `toml:"ONELOGIN_CLIENT_ID"`
	ClientSecret string `toml:"ONELOGIN_CLIENT_SECRET"`
	MFA          bool   `toml:"ONELOGIN_MFA"`
}
type onelogin struct {
	config Config
}

func New(config Config) *onelogin {
	return &onelogin{config: config}
}
