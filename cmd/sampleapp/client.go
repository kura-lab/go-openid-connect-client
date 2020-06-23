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
func setFormPost() {
	cached.Set("FormPost", true, cache.DefaultExpiration)
}

func isFormPost() bool {

	if formPost, found := cached.Get("FormPost"); found {
		log.Info("load form post from cache")
		return formPost.(bool)
	}

	log.Info("failed to load form post status")
	return false
}

func setResponseType(responseType string) {
	cached.Set("ResponseType", responseType, cache.DefaultExpiration)
}

func getResponseType() string {

	if responseType, found := cached.Get("ResponseType"); found {
		log.Info("load response type from cache")
		return responseType.(string)
	}

	log.Warn("failed to load response type")
	return ""
}
