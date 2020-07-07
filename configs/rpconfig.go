package configs

// Constants for RP and OP.
const (
	RedirectURI           = "https://rp.example.com/callback"
	PostLogoutRedirectURI = "https://rp.example.com/logout"
	OIDCConfigURI         = "https://op.example.com/.well-known/openid-configuration"
)

// GetClientIDFromSecureStore is function to load client id.
func GetClientIDFromSecureStore() string {
	/*
		Notice: client credentials should be hard coded in source code. you should store its in secure data store.
		e.g. AWS Secret Manager etc
	*/
	return "YOUR_CLIENT_ID"
}

// GetClientSecretFromSecureStore is function to load client secret.
func GetClientSecretFromSecureStore() string {
	/*
		Notice: client credentials should be hard coded in source code. you should store its in secure data store.
		e.g. AWS Secret Manager etc
	*/
	return "YOUR_CLIENT_SECRET"
}
