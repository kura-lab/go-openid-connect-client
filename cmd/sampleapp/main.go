package main

import (
	"log"
	"net/http"
	"time"

	"github.com/kura-lab/go-openid-connect-client/configs"
	"github.com/kura-lab/go-openid-connect-client/internal/apps/sampleapp/pkg/credential"
	"github.com/kura-lab/go-openid-connect-client/internal/apps/sampleapp/pkg/rand"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/display"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsetype"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/scope"
	mycallback "github.com/kura-lab/go-openid-connect-client/pkg/callback"
	"github.com/kura-lab/go-openid-connect-client/pkg/idtoken"
	"github.com/kura-lab/go-openid-connect-client/pkg/token"
	"github.com/kura-lab/go-openid-connect-client/pkg/userinfo"
)

func init() {
	log.SetFlags(log.Lshortfile)
}

func main() {
	// register handlers with multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:8080/index", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/index", index)
	mux.HandleFunc("/authentication", authentication)
	mux.HandleFunc("/callback", callback)

	// server settings
	server := &http.Server{
		Addr:           "0.0.0.0:8080",
		Handler:        mux,
		ReadTimeout:    time.Second * 10,
		WriteTimeout:   time.Second * 600,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	renderIndex(w)
}

func authentication(w http.ResponseWriter, r *http.Request) {
	log.Println("-- authentication started --")

	// generate state and nonce and store in cookie
	state := rand.GenerateRandomString(32)
	stateCookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, stateCookie)
	nonce := rand.GenerateRandomString(32)
	nonceCookie := &http.Cookie{
		Name:     "nonce",
		Value:    nonce,
		HttpOnly: true,
	}
	http.SetCookie(w, nonceCookie)
	log.Println("stored state and nonce in session")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Println("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to get openid configuration")

	// generate URL to request to authorization endpoint
	authorizationPotinter := authorization.NewAuthorization(
		oIDCConfigResponse,
		credential.GetClientIDValue(),
		configs.RedirectURI,
		authorization.ResponseType(responsetype.Code),
		authorization.Scope(scope.OpenID, scope.Email),
		authorization.Display(display.Touch),
		authorization.State(state),
		authorization.Nonce(nonce),
	)

	url, err := authorizationPotinter.GenerateURL()
	if err != nil {
		log.Println("failed to generate authorization URL")
		renderUnexpectedError(w)
		return
	}
	log.Println("generated authorization endpoint url and redirect the url")

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusMovedPermanently)

	log.Println("-- authentication completed --")
}

func callback(w http.ResponseWriter, r *http.Request) {
	log.Println("-- callback started --")

	// parse callback query
	callbackPointer := mycallback.NewCallback(mycallback.URI(r.URL))
	if err := callbackPointer.Parse(); err != nil {
		log.Println("failed to parse callback query")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to parse callback query")

	// verify state parameter
	storedState, err := r.Cookie("state")
	if err != nil {
		log.Println("failed to extract state in cookie")
		renderUnexpectedError(w)
		return
	}
	stateCookie := &http.Cookie{
		Name:   "state",
		MaxAge: -1,
	}
	http.SetCookie(w, stateCookie)

	statePass, err := callbackPointer.VerifyState(storedState.Value)
	if err != nil {
		log.Println("state does not match stored one")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to verify state parameter")

	// check whether error parameter exists in callback query
	callbackResponse := callbackPointer.Response()
	if callbackResponse.Error != "" {
		log.Println("error: " + callbackResponse.Error)
		log.Println("error_description: " + callbackResponse.ErrorDescription)
		log.Println("error_uri: " + callbackResponse.ErrorURI)
		renderUnexpectedError(w)
		return
	}
	log.Println("error didn't exist in callback query")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Println("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to get openid configuration")

	// request to token endpoint
	tokenPointer := token.NewToken(
		oIDCConfigResponse,
		credential.GetClientIDValue(),
		credential.GetClientSecretValue(),
		token.StatePass(statePass),
		token.GrantType("authorization_code"),
		token.AuthorizationCode(callbackResponse.AuthorizationCode),
		token.RedirectURI(configs.RedirectURI),
	)

	if err := tokenPointer.Request(); err != nil {
		log.Println("failed to request token endpoint")
		renderUnexpectedError(w)
		return
	}

	tokenResponse := tokenPointer.Response()
	log.Println("status: " + tokenResponse.Status)

	if tokenResponse.StatusCode != http.StatusOK {
		log.Println("error: ", tokenResponse.Error)
		log.Println("error_description: ", tokenResponse.ErrorDescription)
		if tokenResponse.Error == "invalid_grant" {
			renderUnauthorizedError(w)
			return
		}
		log.Println("token response was error")
		renderUnexpectedError(w)
		return
	}
	log.Println("access token: " + tokenResponse.AccessToken)
	log.Println("token type: " + tokenResponse.TokenType)
	log.Println("refresh token: " + tokenResponse.RefreshToken)
	log.Println("expires in: ", tokenResponse.ExpiresIn)
	log.Println("id token: " + tokenResponse.IDToken)
	log.Println("requested to token endpoint")

	// verify id token's header
	iDTokenPointer, err := idtoken.NewIDToken(
		oIDCConfigResponse,
		tokenResponse.IDToken,
	)
	if err != nil {
		log.Println("failed to decode id token")
		renderUnexpectedError(w)
		return
	}

	if err := iDTokenPointer.VerifyIDTokenHeader(); err != nil {
		log.Println("invalid claim in id token header")
		renderUnexpectedError(w)
		return
	}
	iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()
	log.Println("typ: ", iDTokenPointerHeader.Type)
	log.Println("kid: ", iDTokenPointerHeader.KeyID)
	log.Println("alg: ", iDTokenPointerHeader.Algorithm)
	log.Println("verified id token's header")

	// get jwks response
	jWKsResponse, err := getJWKsResponse(oIDCConfigResponse)
	if err != nil {
		log.Println("failed to get jwks response")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to get jwks response")

	// verify id token's signature
	if err := iDTokenPointer.VerifySignature(jWKsResponse); err != nil {
		log.Println("invalid id token signature")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to verify signature")

	// verify claims in id token's payload
	storedNonce, err := r.Cookie("nonce")
	if err != nil {
		log.Println("failed to extract nonce in cookie")
		renderUnexpectedError(w)
		return
	}
	nonceCookie := &http.Cookie{
		Name:   "nonce",
		MaxAge: -1,
	}
	http.SetCookie(w, nonceCookie)
	log.Println("stored nonce: ", storedNonce.Value)

	err = iDTokenPointer.VerifyPayloadClaims(
		idtoken.Issuer(),
		idtoken.Audience(credential.GetClientIDValue()),
		idtoken.Nonce(storedNonce.Value),
		idtoken.DurationIssuedAt(600),
	)
	if err != nil {
		log.Println("invalid claim in id token payload")
		renderUnexpectedError(w)
		return
	}

	idTokenPayload := iDTokenPointer.GetIDTokenPayload()

	// verify following claims according to your requirements
	//log.Println("Expiration: ", idTokenPayload.Expiration)
	//log.Println("AuthTime: ", idTokenPayload.AuthTime)
	//log.Println("AuthenticationMethodReference: ", idTokenPayload.AuthenticationMethodReference)
	//log.Println("AuthenticationContextReference: ", idTokenPayload.AuthenticationContextReference)

	log.Println("success to verify claims in id token payload")

	// request to userinfo endpoint
	userInfoPointer := userinfo.NewUserInfo(
		oIDCConfigResponse,
		tokenResponse.AccessToken,
	)

	if err := userInfoPointer.Request(); err != nil {
		log.Println("failed to request userinfo endpoint")
		renderUnexpectedError(w)
		return
	}
	log.Println("requested to userinfo endpoint")

	userInfoResponse := userInfoPointer.Response()
	log.Println("status: " + userInfoResponse.Status)

	if userInfoResponse.StatusCode != http.StatusOK {
		log.Println("WWW-Authenticate Bearer")
		log.Println("realm: ", userInfoResponse.WWWAuthenticate.Realm)
		log.Println("scope: ", userInfoResponse.WWWAuthenticate.Scope)
		log.Println("error: ", userInfoResponse.WWWAuthenticate.Error)
		log.Println("error_description: ", userInfoResponse.WWWAuthenticate.ErrorDescription)
		log.Println("userinfo response was error")
		renderUnexpectedError(w)
		return
	}
	log.Println("requested to userinfo endpoint")

	// verify sub claim
	if idTokenPayload.Subject != userInfoResponse.Subject {
		log.Println("id token sub: ", idTokenPayload.Subject)
		log.Println("userinfo sub: ", userInfoResponse.Subject)
		log.Println("userinfo's sub not match id token's one")
		renderUnexpectedError(w)
		return
	}
	log.Println("success to verify sub claim")

	// request to token endpoint as refresh
	// note: you don't need to refresh when access token is valid
	refreshPointer := token.NewToken(
		oIDCConfigResponse,
		credential.GetClientIDValue(),
		credential.GetClientSecretValue(),
		token.StatePass(statePass),
		token.GrantType("refresh_token"),
		token.RefreshToken(tokenResponse.RefreshToken),
	)

	if err := refreshPointer.Request(); err != nil {
		log.Println("failed to request token endpoint as refresh")
		renderUnexpectedError(w)
		return
	}

	refreshResponse := refreshPointer.Response()
	if refreshResponse.StatusCode != http.StatusOK {
		log.Println("error: ", refreshResponse.Error)
		log.Println("error_description: ", refreshResponse.ErrorDescription)
		log.Println("token response was error as refresh")
		renderUnexpectedError(w)
		return
	}
	log.Println("access token: " + refreshResponse.AccessToken)
	log.Println("token type: " + refreshResponse.TokenType)
	log.Println("expires in: ", refreshResponse.ExpiresIn)
	log.Println("requested to token endpoint as refresh")

	renderCallback(w, userInfoResponse)

	log.Println("-- callback completed --")
}
