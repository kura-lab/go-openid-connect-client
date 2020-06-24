package main

import (
	"errors"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

func getJWKsResponse(oIDCConfigResponse oidcconfig.Response) (jwks.Response, error) {
	if data, found := cached.Get("JWKsResponse"); found {
		log.Info("load jwks response from cache")
		return data.(jwks.Response), nil
	}

	// request to jwks uri to get jwk set
	jWKsPointer := jwks.NewJWKs(oIDCConfigResponse)

	if err := jWKsPointer.Request(); err != nil {
		log.WithFields(log.Fields{
			"status": jWKsPointer.Response().Status,
			"body":   jWKsPointer.Response().Body,
		}).Fatal("failed to request jwks uri")
		return jwks.Response{}, errors.New("failed to request jwks uri")
	}

	response := jWKsPointer.Response()
	log.WithFields(log.Fields{
		"status": response.Status,
		"body":   response.Body,
	}).Info("requested to jwks uri")

	if response.StatusCode != http.StatusOK {
		log.Warn("jwks response was error")
		return jwks.Response{}, errors.New("jwks response was error")
	}

	log.Info("request to jwks response and cache it")
	cached.Set("JWKsResponse", response, cache.DefaultExpiration)

	return response, nil
}
