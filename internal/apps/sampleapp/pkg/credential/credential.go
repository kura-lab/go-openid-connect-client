package credential

import (
	"log"
	"time"

	"github.com/kura-lab/go-openid-connect-client/configs"
	"github.com/patrickmn/go-cache"
)

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
	clientID := configs.GetClientIDFromSecureStore()
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
	clientSecret := configs.GetClientSecretFromSecureStore()
	cached.Set("ClientSecret", clientSecret, cache.DefaultExpiration)

	return clientSecret
}
