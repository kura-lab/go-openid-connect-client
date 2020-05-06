package configs

// Constants for RP and OP.
const (
	RedirectURI   = "https://rp.example.com/callback"
	OIDCConfigURI = "https://op.example.com/.well-known/openid-configuration"
)

func getClientIDFromSecureStore() string {
	/*
		Notice: client credentials should be hard coded in source code. you should store its in secure data store.
		e.g. AWS Secret Manager etc
	*/
	return "YOUR_CLIENT_ID"
}

func getClientSecretFromSecureStore() string {
	/*
		Notice: client credentials should be hard coded in source code. you should store its in secure data store.
		e.g. AWS Secret Manager etc
	*/
	return "YOUR_CLIENT_SECRET"
}
