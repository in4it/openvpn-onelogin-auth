# OpenVPN Onelogin Auth

## Installation

Download the binary from the releases or build the app yourself with "make". Copy the binary to /bin/openvpn-onelogin-auth and add these lines to your openvpn.conf:

```
### OpenVPN auth
auth-user-pass-verify /bin/openvpn-onelogin-auth via-env
script-security 3
```

Create a config file based on onelogin.conf.template and put it in /etc/openvpn/onelogin.conf. This contains the API URL and the credentials to be able to authenticate against the onelogin API.

