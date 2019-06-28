# OpenVPN Onelogin Auth

## Installation

Download the binary from the releases or build the app yourself with "make". Copy the binary to /bin/openvpn-onelogin-auth and add these lines to your openvpn.conf:

```
### OpenVPN auth
auth-user-pass-verify /bin/openvpn-onelogin-auth via-env
script-security 3
```

Create a config file based on onelogin.conf.template and put it in /etc/openvpn/onelogin.conf. This contains the API URL and the credentials to be able to authenticate against the onelogin API.

## OneLogin setup

Follow the [OneLogin documentation](https://developers.onelogin.com/api-docs/1/getting-started/working-with-api-credentials#creating-an-api-credentialpair) on how to setup a pair of API credentials.

Mind that the Credentials need the scope `Manage Users`.

## MFA

This tool will use the **first** multi factor method associated with your
account and requires you to append the code to your password when
authenticating. The last 6 digits will be treated as the MFA code.
