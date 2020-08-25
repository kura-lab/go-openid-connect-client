package main

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/kura-lab/go-openid-connect-client/configs"
	"github.com/kura-lab/go-openid-connect-client/internal/apps/sampleapp/pkg/rand"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/display"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/responsemode"
	"github.com/kura-lab/go-openid-connect-client/pkg/authorization/scope"
	mycallback "github.com/kura-lab/go-openid-connect-client/pkg/callback"
	"github.com/kura-lab/go-openid-connect-client/pkg/client"
	"github.com/kura-lab/go-openid-connect-client/pkg/idtoken"
	mylogout "github.com/kura-lab/go-openid-connect-client/pkg/logout"
	"github.com/kura-lab/go-openid-connect-client/pkg/token"
	"github.com/kura-lab/go-openid-connect-client/pkg/token/granttype"
	"github.com/kura-lab/go-openid-connect-client/pkg/userinfo"
	"github.com/kura-lab/go-openid-connect-client/pkg/webfinger"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return "", fmt.Sprintf("%s:%d", filename, f.Line)
		},
	})
}

func main() {
	// register handlers with multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/index", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/index", index)
	mux.HandleFunc("/webfinger", registrationViaWebfinger)
	mux.HandleFunc("/registration", registration)
	mux.HandleFunc("/rp/", initiateLoginURI)
	mux.HandleFunc("/authentication", authentication)
	mux.HandleFunc("/callback", callback)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/backchannel_logout", backChannelLogout)

	// server settings
	server := &http.Server{
		Addr:           "127.0.0.1:8080",
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

func initiateLoginURI(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- initiate login uri started --")

	// parse path (/rp/<rp_id>/rp-3rd_party-init-login/<client_id>)
	clientID := strings.Replace(r.URL.Path, "/rp/rp_kura/rp-3rd_party-init-login/", "", 1)

	if clientID != getClientID() {
		log.WithFields(log.Fields{
			"initiate login uri": r.URL.Path,
		}).Warn("invalid initiate login uri")
		renderUnexpectedError(w)
		return
	}

	log.WithFields(log.Fields{
		"client_id":          clientID,
		"initiate login uri": r.URL.Path,
	}).Info("redirected to sso endpoint(/authentication) from initiate login uri")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", "/authentication")
	w.WriteHeader(http.StatusMovedPermanently)

	log.Info("-- initiate login uri completed --")
}

func registrationViaWebfinger(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- registration via webfinger started --")

	if r.Method == http.MethodGet {
		renderWebfinger(w)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Fatal("failed to parse post form")
		renderUnexpectedError(w)
		return
	}
	webfingerHost := r.Form.Get("webfinger_host")

	acctURISyntax := r.Form.Get("resource_acct_uri_syntax")
	uRISyntax := r.Form.Get("resource_uri_syntax")

	var webfingerPointer *webfinger.Webfinger
	if acctURISyntax != "" {
		webfingerPointer = webfinger.NewWebfinger(
			webfingerHost,
			webfinger.AcctURI("acct:"+acctURISyntax, "rp.certification.openid.net:8080"),
		)
	} else if uRISyntax != "" {
		webfingerPointer = webfinger.NewWebfinger(
			webfingerHost,
			webfinger.URL(uRISyntax),
		)
	} else {
		log.Fatal("unsufficient parameter. require resource parameter")
		renderUnexpectedError(w)
		return
	}

	if err := webfingerPointer.Request(); err != nil {
		log.Fatal("failed to request webfinger")
	}

	responseWebfinger := webfingerPointer.Response()
	log.WithFields(log.Fields{
		"status": responseWebfinger.Status,
		"body":   responseWebfinger.Body,
	}).Info("requested to client registration endpoint")

	if responseWebfinger.StatusCode != http.StatusOK {
		log.Fatal("failed to request webfinger")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"subject": responseWebfinger.Subject,
		"rel":     responseWebfinger.Links[0].Rel,
		"href":    responseWebfinger.Links[0].Href,
	}).Info("success to request webfinger")

	setOIDCConfigURI(responseWebfinger.Links[0].Href + "/.well-known/openid-configuration")

	responseType := r.Form.Get("response_type")
	setResponseType(responseType)

	responseMode := r.Form.Get("response_mode")
	if responseMode == "form_post" {
		setFormPost()
	}

	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	registrationPointer := client.NewRegistration(
		oIDCConfigResponse,
		[]string{
			configs.RedirectURI,
		},
		client.ApplicationType("web"),
		client.ResponseTypes([]string{
			"code",
		}),
		client.GrantTypes([]string{
			"authorization_code",
			"refresh_token",
		}),
		client.Name("RP Kura"),
		client.SubjectType("pairwise"),
		client.TokenEndpointAuthMethod("client_secret_basic"),
		client.Contacts([]string{"mkurahay@gmail.com"}),
		client.PostLogoutRedirectURIs([]string{configs.PostLogoutRedirectURI}),
	)

	err = registrationPointer.Request()
	if err != nil {
		log.WithFields(log.Fields{
			"status": registrationPointer.Response().Status,
			"body":   registrationPointer.Response().Body,
		}).Fatal("failed to request client registration")
		renderUnexpectedError(w)
		return
	}

	response := registrationPointer.Response()
	log.WithFields(log.Fields{
		"status": response.Status,
		"body":   response.Body,
	}).Info("requested to client registration endpoint")

	if response.StatusCode != http.StatusCreated {
		log.WithFields(log.Fields{
			"error":             response.Error,
			"error_description": response.ErrorDescription,
		}).Fatal("client registration response was error")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"client_name":               response.ClientName,
		"client_id":                 response.ClientID,
		"client_secret":             response.ClientSecret,
		"registration_client_uri":   response.RegistrationClientURI,
		"registration_access_token": response.RegistrationAccessToken,
	}).Info("success to register client")

	setClientID(response.ClientID)
	setClientSecret(response.ClientSecret)

	renderRegistrationComplete(w, response)

	log.Info("-- registration via webfinger completed --")
}

func registration(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- registration started --")

	if r.Method == http.MethodGet {
		renderRegistration(w)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Fatal("failed to parse post form")
		renderUnexpectedError(w)
		return
	}
	oIDCConfigURI := r.Form.Get("oidc_config_uri")
	setOIDCConfigURI(oIDCConfigURI)

	responseType := r.Form.Get("response_type")
	setResponseType(responseType)

	responseMode := r.Form.Get("response_mode")
	if responseMode == "form_post" {
		setFormPost()
	}

	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	registrationPointer := client.NewRegistration(
		oIDCConfigResponse,
		[]string{
			configs.RedirectURI,
		},
		client.ApplicationType("web"),
		client.ResponseTypes([]string{
			"code",
		}),
		client.GrantTypes([]string{
			"authorization_code",
			"refresh_token",
		}),
		client.Name("RP Kura"),
		client.SubjectType("pairwise"),
		client.TokenEndpointAuthMethod("client_secret_basic"),
		client.Contacts([]string{"mkurahay@gmail.com"}),
		client.PostLogoutRedirectURIs([]string{configs.PostLogoutRedirectURI}),
	)

	err = registrationPointer.Request()
	if err != nil {
		log.WithFields(log.Fields{
			"status": registrationPointer.Response().Status,
			"body":   registrationPointer.Response().Body,
		}).Fatal("failed to request client registration")
		renderUnexpectedError(w)
		return
	}

	response := registrationPointer.Response()
	log.WithFields(log.Fields{
		"status": response.Status,
		"body":   response.Body,
	}).Info("requested to client registration endpoint")

	if response.StatusCode != http.StatusCreated {
		log.WithFields(log.Fields{
			"error":             response.Error,
			"error_description": response.ErrorDescription,
		}).Fatal("client registration response was error")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"client_name":               response.ClientName,
		"client_id":                 response.ClientID,
		"client_secret":             response.ClientSecret,
		"registration_client_uri":   response.RegistrationClientURI,
		"registration_access_token": response.RegistrationAccessToken,
	}).Info("success to register client")

	setClientID(response.ClientID)
	setClientSecret(response.ClientSecret)

	renderRegistrationComplete(w, response)

	log.Info("-- registration completed --")
}

func authentication(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- authentication started --")

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
	log.Info("stored state and nonce in session")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	// load settings from cache
	var responseMode string
	if isFormPost() {
		responseMode = responsemode.FormPost
	} else {
		responseMode = ""
	}
	responseType := getResponseType()

	// generate URL to request to authorization endpoint
	authorizationPotinter := authorization.NewAuthorization(
		oIDCConfigResponse,
		getClientID(),
		configs.RedirectURI,
		authorization.ResponseType(responseType),
		authorization.Scope(scope.OpenID, scope.Email, scope.Profile, scope.Address, scope.Phone),
		authorization.Display(display.Touch),
		authorization.State(state),
		authorization.Nonce(nonce),
		authorization.ResponseMode(responseMode),
	)

	url, err := authorizationPotinter.GenerateURL()
	if err != nil {
		log.Fatal("failed to generate authorization URL")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"authorization url": url,
	}).Info("generated authorization endpoint url and redirect the url")

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusMovedPermanently)

	log.Info("-- authentication completed --")
}

func callback(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- callback started --")

	var callbackPointer *mycallback.Callback
	if isFormPost() {
		log.Info("response mode is form post")
		err := r.ParseForm()
		if err != nil {
			log.Info("failed to parse post form")
			renderUnexpectedError(w)
			return
		}
		// parse callback form post
		callbackPointer = mycallback.NewCallback(mycallback.Form(r.Form))
	} else {
		log.Info("response mode is query")
		// parse callback query
		callbackPointer = mycallback.NewCallback(mycallback.URI(r.URL))
	}
	if err := callbackPointer.Parse(); err != nil {
		log.Fatal("failed to parse callback query")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to parse callback form post or query")

	// verify state parameter
	storedState, err := r.Cookie("state")
	if err != nil {
		log.Fatal("failed to extract state in cookie")
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
		log.Fatal("state does not match stored one")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to verify state parameter")

	// check whether error parameter exists in callback query
	callbackResponse := callbackPointer.Response()
	if callbackResponse.Error != "" {
		log.WithFields(log.Fields{
			"error":             callbackResponse.Error,
			"error_description": callbackResponse.ErrorDescription,
			"error_uri":         callbackResponse.ErrorURI,
		}).Fatal("generated authorization endpoint url and redirect the url")
		renderUnexpectedError(w)
		return
	}
	log.Info("error didn't exist in callback form post or query")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	// request to token endpoint
	tokenPointer := token.NewToken(
		oIDCConfigResponse,
		getClientID(),
		getClientSecret(),
		token.StatePass(statePass),
		token.GrantType(granttype.AuthorizationCode),
		token.AuthorizationCode(callbackResponse.AuthorizationCode),
		token.RedirectURI(configs.RedirectURI),
	)

	if err := tokenPointer.Request(); err != nil {
		log.WithFields(log.Fields{
			"status": tokenPointer.Response().Status,
			"body":   tokenPointer.Response().Body,
		}).Fatal("failed to request token endpoint")
		renderUnexpectedError(w)
		return
	}

	tokenResponse := tokenPointer.Response()
	log.WithFields(log.Fields{
		"status": tokenResponse.Status,
		"body":   tokenResponse.Body,
	}).Info("token response")

	if tokenResponse.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{
			"error":             tokenResponse.Error,
			"error_description": tokenResponse.ErrorDescription,
		}).Info("token response was error")
		if tokenResponse.Error == "invalid_grant" {
			renderUnauthorizedError(w)
			return
		}
		log.Fatal("token response was unexpected error")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"access_token":  tokenResponse.AccessToken,
		"token_type":    tokenResponse.TokenType,
		"refresh_token": tokenResponse.RefreshToken,
		"expires_in":    tokenResponse.ExpiresIn,
		"id_token":      tokenResponse.IDToken,
	}).Info("requested to token endpoint")

	// verify id token's header
	iDTokenPointer, err := idtoken.NewIDToken(
		oIDCConfigResponse,
		tokenResponse.IDToken,
	)
	if err != nil {
		log.Fatal("failed to decode id token")
		renderUnexpectedError(w)
		return
	}

	if err := iDTokenPointer.VerifyIDTokenHeader(); err != nil {
		log.Warn("invalid claim in id token header")
		renderUnexpectedError(w)
		return
	}
	iDTokenPointerHeader := iDTokenPointer.GetIDTokenHeader()
	log.WithFields(log.Fields{
		"typ": iDTokenPointerHeader.Type,
		"kid": iDTokenPointerHeader.KeyID,
		"alg": iDTokenPointerHeader.Algorithm,
	}).Info("verified id token's header")

	// get jwks response
	jWKsResponse, err := getJWKsResponse(oIDCConfigResponse)
	if err != nil {
		log.Fatal("failed to get jwks response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get jwks response")

	// verify id token's signature
	if err := iDTokenPointer.VerifySignature(jWKsResponse); err != nil {
		log.Fatal("invalid id token signature")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to verify signature")

	// verify claims in id token's payload
	storedNonce, err := r.Cookie("nonce")
	if err != nil {
		log.Fatal("failed to extract nonce in cookie")
		renderUnexpectedError(w)
		return
	}
	nonceCookie := &http.Cookie{
		Name:   "nonce",
		MaxAge: -1,
	}
	http.SetCookie(w, nonceCookie)
	log.Info("stored nonce: ", storedNonce.Value)

	err = iDTokenPointer.VerifyPayloadClaims(
		idtoken.Issuer(),
		idtoken.Audience(getClientID()),
		idtoken.Nonce(storedNonce.Value),
		idtoken.DurationIssuedAt(600),
	)
	if err != nil {
		log.Fatal("invalid claim in id token payload")
		renderUnexpectedError(w)
		return
	}

	iDTokenPayload := iDTokenPointer.GetIDTokenPayload()

	// verify following claims according to your requirements
	//log.Info("Expiration: ", iDTokenPayload.Expiration)
	//log.Info("AuthTime: ", iDTokenPayload.AuthTime)
	//log.Info("AuthenticationMethodReference: ", iDTokenPayload.AuthenticationMethodReference)
	//log.Info("AuthenticationContextReference: ", iDTokenPayload.AuthenticationContextReference)

	log.Info("success to verify claims in id token payload")

	// request to userinfo endpoint
	userInfoPointer := userinfo.NewUserInfo(
		oIDCConfigResponse,
		tokenResponse.AccessToken,
	)

	if err := userInfoPointer.Request(); err != nil {
		log.WithFields(log.Fields{
			"status": userInfoPointer.Response().Status,
			"body":   userInfoPointer.Response().Body,
		}).Fatal("failed to request userinfo endpoint")
		renderUnexpectedError(w)
		return
	}
	userInfoResponse := userInfoPointer.Response()
	log.WithFields(log.Fields{
		"status": userInfoResponse.Status,
		"body":   userInfoResponse.Body,
	}).Info("requested to userinfo endpoint")

	if userInfoResponse.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{
			"realm":             userInfoResponse.WWWAuthenticate.Realm,
			"scope":             userInfoResponse.WWWAuthenticate.Scope,
			"error":             userInfoResponse.WWWAuthenticate.Error,
			"error_description": userInfoResponse.WWWAuthenticate.ErrorDescription,
		}).Fatal("userinfo response was error. WWW-Authenticate Bearer")
		renderUnexpectedError(w)
		return
	}

	// verify sub claim
	if iDTokenPayload.Subject != userInfoResponse.Subject {
		log.WithFields(log.Fields{
			"id token sub": iDTokenPayload.Subject,
			"userinfo sub": userInfoResponse.Subject,
		}).Fatal("userinfo's sub not match id token's one")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to verify sub claim")

	// request to token endpoint as refresh
	// note: you don't need to refresh when access token is valid
	//refreshPointer := token.NewToken(
	//	oIDCConfigResponse,
	//	getClientID(),
	//	getClientSecret(),
	//	token.GrantType(granttype.RefreshToken),
	//	token.RefreshToken(tokenResponse.RefreshToken),
	//)

	//if err := refreshPointer.Request(); err != nil {
	//	log.WithFields(log.Fields{
	//		"status": refreshPointer.Response().Status,
	//		"body":   refreshPointer.Response().Body,
	//	}).Fatal("failed to request token endpoint as refresh")
	//	renderUnexpectedError(w)
	//	return
	//}

	//refreshResponse := refreshPointer.Response()
	//log.WithFields(log.Fields{
	//	"status": refreshResponse.Status,
	//	"body":   refreshResponse.Body,
	//}).Info("requested to token endpoint as refresh")
	//if refreshResponse.StatusCode != http.StatusOK {
	//	log.WithFields(log.Fields{
	//		"error":             refreshResponse.Error,
	//		"error_description": refreshResponse.ErrorDescription,
	//	}).Fatal("token response was error as refresh")
	//	renderUnexpectedError(w)
	//	return
	//}
	//log.WithFields(log.Fields{
	//	"access_token": refreshResponse.AccessToken,
	//	"token_type":   refreshResponse.TokenType,
	//	"expires_in":   refreshResponse.ExpiresIn,
	//}).Info("requested to token endpoint as refresh")

	renderCallback(w, userInfoResponse)

	log.Info("-- callback completed --")
}

func logout(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- logout started --")

	// generate state and nonce and store in cookie
	state := rand.GenerateRandomString(32)
	stateCookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
	}
	http.SetCookie(w, stateCookie)
	log.Info("stored state in session")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	// generate URL to redirect to logout endpoint
	logoutPotinter := mylogout.NewLogout(
		oIDCConfigResponse,
		mylogout.IDTokenHint("ID_TOKEN_HINT"),
		mylogout.PostLogoutRedirectURI(configs.PostLogoutRedirectURI),
		mylogout.State(state),
	)

	url, err := logoutPotinter.GenerateURL()
	if err != nil {
		log.Fatal("failed to generate logout URL")
		renderUnexpectedError(w)
		return
	}
	log.WithFields(log.Fields{
		"logout url": url,
	}).Info("generated logout endpoint url and redirect the url")

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusMovedPermanently)

	log.Info("-- logout completed --")
}

func backChannelLogout(w http.ResponseWriter, r *http.Request) {

	log.WithFields(log.Fields{
		"method": r.Method,
		"url":    r.URL,
	}).Info("-- back-channel logout started --")

	err := r.ParseForm()
	if err != nil {
		log.Fatal("failed to parse post form")
		renderUnexpectedError(w)
		return
	}
	logoutToken := r.Form.Get("logout_token")

	// get openid configuration
	oIDCConfigResponse, err := getOIDCConfigResponse()
	if err != nil {
		log.Fatal("failed to get openid configuration response")
		renderUnexpectedError(w)
		return
	}
	log.Info("success to get openid configuration")

	log.Info("-- back-channel logout completed --")
}
