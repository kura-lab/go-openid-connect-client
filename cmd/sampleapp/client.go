package main

import (
	"log"

	"github.com/patrickmn/go-cache"
)

func setClientID(clientID string) {
	cached.Set("ClientID", clientID, cache.DefaultExpiration)
}

func getClientID() string {

	if clientID, found := cached.Get("ClientID"); found {
		log.Println("load client id from cache")
		return clientID.(string)
	}

	log.Println("failed to load client id")
	return ""
}

func setClientSecret(clientSecret string) {
	cached.Set("ClientSecret", clientSecret, cache.DefaultExpiration)
}

func getClientSecret() string {

	if clientSecret, found := cached.Get("ClientSecret"); found {
		log.Println("load client secret from cache")
		return clientSecret.(string)
	}

	log.Println("failed to load client secret")
	return ""
}
