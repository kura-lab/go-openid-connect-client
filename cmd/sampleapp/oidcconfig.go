package main

import (
	"errors"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

func setOIDCConfigURI(oIDCConfigURI string) {
	cached.Set("OIDCConfigURI", oIDCConfigURI, cache.DefaultExpiration)
}

func getOIDCConfigResponse() (oidcconfig.Response, error) {
	if data, found := cached.Get("OIDCConfigResponse"); found {
		log.Info("load openid configuration response from cache")
		return data.(oidcconfig.Response), nil
	}

	oIDCConfigURI, found := cached.Get("OIDCConfigURI")
	if !found {
		log.Warn("failed to load OIDCConfigURI")
		return oidcconfig.Response{}, nil
	}

	// request to .well-known endpoint to get openid-configuration
	oIDCConfigPointer := oidcconfig.New(
		oIDCConfigURI.(string),
	)
	if err := oIDCConfigPointer.Request(); err != nil {
		log.WithFields(log.Fields{
			"status": oIDCConfigPointer.Response().Status,
			"body":   oIDCConfigPointer.Response().Body,
		}).Fatal("failed to request openid configuration")
		return oidcconfig.Response{}, errors.New("failed to request openid configuration")
	}

	response := oIDCConfigPointer.Response()
	log.WithFields(log.Fields{
		"status": response.Status,
		"body":   response.Body,
	}).Info("requested to openid configuration")

	if response.StatusCode != http.StatusOK {
		log.Warn("openid configuration response was error")
		return oidcconfig.Response{}, errors.New("openid configuration response was error")
	}

	log.Info("request to openid configuration response and cache it")
	cached.Set("OIDCConfigResponse", response, cache.DefaultExpiration)

	return response, nil
}
