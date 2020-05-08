package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/kura-lab/go-openid-connect-client/configs"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/patrickmn/go-cache"
)

var cached *cache.Cache

func init() {
	// create cache of client id and client secret
	cached = cache.New(24*time.Hour, 25*time.Hour)
}

func getOIDCConfigResponse() (oidcconfig.Response, error) {
	if data, found := cached.Get("OIDCConfigResponse"); found {
		log.Println("load openid configuration response from cache")
		return data.(oidcconfig.Response), nil
	}

	// request to .well-known endpoint to get openid-configuration
	oIDCConfigPointer := oidcconfig.New(
		configs.OIDCConfigURI,
	)
	if err := oIDCConfigPointer.Request(); err != nil {
		log.Println("failed to request openid configuration")
		return oidcconfig.Response{}, errors.New("failed to request openid configuration")
	}

	response := oIDCConfigPointer.Response()
	log.Println("status: " + response.Status)

	if response.StatusCode != http.StatusOK {
		log.Println("openid configuration response was error")
		return oidcconfig.Response{}, errors.New("openid configuration response was error")
	}

	log.Println("request to openid configuration response and cache it")
	cached.Set("OIDCConfigResponse", response, cache.DefaultExpiration)

	return response, nil
}
