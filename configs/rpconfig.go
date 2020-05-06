package configs

import (
	"log"
	"time"

	"github.com/patrickmn/go-cache"
)

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

var cached *cache.Cache

func init() {
	// create cache of client id and client secret
	cached = cache.New(24*time.Hour, 25*time.Hour)
}

// GetClientIDValue is function to load client id from cache or secure data store.
func GetClientIDValue() string {
	if data, found := cached.Get("ClientID"); found {
		log.Println("load client id from cache")
		return data.(string)
	}

	log.Println("load client id from secure data store and cache it")
	clientID := getClientIDFromSecureStore()
	cached.Set("ClientID", clientID, cache.DefaultExpiration)

	return clientID
}

// GetClientSecretValue is function to load client secret from cache or secure data store.
func GetClientSecretValue() string {
	if data, found := cached.Get("ClientSecret"); found {
		log.Println("load client secret from cache")
		return data.(string)
	}

	log.Println("load client secret from secure data store and cache it")
	clientSecret := getClientSecretFromSecureStore()
	cached.Set("ClientSecret", clientSecret, cache.DefaultExpiration)

	return clientSecret
}
