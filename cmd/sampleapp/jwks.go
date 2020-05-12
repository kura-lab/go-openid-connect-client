package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/kura-lab/go-openid-connect-client/pkg/jwks"
	"github.com/kura-lab/go-openid-connect-client/pkg/oidcconfig"
	"github.com/patrickmn/go-cache"
)

func getJWKsResponse(oIDCConfigResponse oidcconfig.Response) (jwks.Response, error) {
	if data, found := cached.Get("JWKsResponse"); found {
		log.Println("load jwks response from cache")
		return data.(jwks.Response), nil
	}

	// request to jwks uri to get jwk set
	jWKsPointer := jwks.NewJWKs(oIDCConfigResponse)

	if err := jWKsPointer.Request(); err != nil {
		log.Println("failed to request jwks uri")
		return jwks.Response{}, errors.New("failed to request jwks uri")
	}

	response := jWKsPointer.Response()
	log.Println("status: " + response.Status)

	if response.StatusCode != http.StatusOK {
		log.Println("jwks response was error")
		return jwks.Response{}, errors.New("jwks response was error")
	}

	log.Println("request to jwks response and cache it")
	cached.Set("JWKsResponse", response, cache.DefaultExpiration)

	return response, nil
}
