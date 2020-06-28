package webfinger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Response is struct for Webfinger Response.
type Response struct {
	Status     string
	StatusCode int
	Body       string
	Subject    string `json:"subject"`
	Links      []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	} `json:"links"`
}

// Webfinger is struct to request Webfinger Endpoint.
type Webfinger struct {
	response Response
	host     string
	resource string
}

// NewWebfinger is Webfinger constructor function.
func NewWebfinger(host string, options ...Option) *Webfinger {
	webfinger := new(Webfinger)
	webfinger.host = host
	for _, option := range options {
		option(webfinger)
	}
	return webfinger
}

// Option is functional option for Webfinger struct initialization.
type Option func(*Webfinger) error

// Email is functional option to add resource parameter of E-Mail Address Syntax.
func Email(email string) Option {
	return func(webfinger *Webfinger) error {
		webfinger.resource = "acct:" + email
		return nil
	}
}

// URL is functional option to add resource parameter of URL Syntax.
func URL(uRL string) Option {
	return func(webfinger *Webfinger) error {
		webfinger.resource = uRL
		return nil
	}
}

// HostnameAndPort is functional option to add resource parameter of Hostname and Port Syntax.
func HostnameAndPort(host string, port string) Option {
	return func(webfinger *Webfinger) error {

		u, _ := url.Parse("")
		u.Scheme = "https"
		u.Host = host + ":" + port

		webfinger.resource = u.String()
		return nil
	}
}

// AcctURI is functional option to add resource parameter of "acct" URI Syntax.
func AcctURI(email string, host string) Option {
	return func(webfinger *Webfinger) error {
		webfinger.resource = "acct:" + url.QueryEscape(email) + "@" + host
		return nil
	}
}

// Request is method to request Webfinger Endpoint.
func (webfinger *Webfinger) Request() (nerr error) {

	u, _ := url.Parse("")
	u.Scheme = "https"
	u.Host = webfinger.host
	u.Path = "/.well-known/webfinger"

	webfingerRequest, err := http.NewRequest(
		http.MethodGet,
		u.String(),
		nil,
	)
	if err != nil {
		nerr = err
		return
	}

	params := webfingerRequest.URL.Query()

	if webfinger.resource != "" {
		params.Add("resource", webfinger.resource)
	} else {
		nerr = errors.New("resource parameter is required")
		return
	}

	params.Add("rel", "http://openid.net/specs/connect/1.0/issuer")

	webfingerRequest.URL.RawQuery = params.Encode()

	response, err := http.DefaultClient.Do(webfingerRequest)
	defer func() {
		if _, err := io.Copy(ioutil.Discard, response.Body); err != nil {
			nerr = err
			return
		}
		if err := response.Body.Close(); err != nil {
			nerr = err
			return
		}
	}()

	if err != nil {
		nerr = err
		return
	}

	buf := bytes.NewBuffer(nil)
	body := bytes.NewBuffer(nil)

	w := io.MultiWriter(buf, body)
	io.Copy(w, response.Body)

	var webfingerResponse Response
	webfinger.response = webfingerResponse
	webfinger.response.Status = response.Status
	webfinger.response.StatusCode = response.StatusCode

	rawBody, err := ioutil.ReadAll(buf)
	if err != nil {
		nerr = err
		return
	}
	webfinger.response.Body = string(rawBody)

	err = json.NewDecoder(body).Decode(&webfinger.response)
	if err != nil {
		nerr = err
		return
	}

	return
}

// Response is getter method of Response struct.
func (webfinger *Webfinger) Response() Response {
	return webfinger.response
}
