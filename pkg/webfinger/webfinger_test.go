package webfinger

import (
	"log"
	"net/http"
	"testing"

	"gopkg.in/h2non/gock.v1"
)

func TestNewWebfingerEmailSyntaxSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/.well-known/webfinger").
		MatchParam("resource", "acct:joe@example.com").
		MatchParam("rel", "http://openid.net/specs/connect/1.0/issuer").
		Reply(200).
		JSON(map[string]interface{}{
			"subject": "acct:joe@example.com",
			"links": []interface{}{
				map[string]string{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": "https://op.example.com",
				},
			},
		})

	webfingerPointer := NewWebfinger(
		"op.example.com",
		Email("acct:joe@example.com"),
	)
	if err := webfingerPointer.Request(); err != nil {
		log.Println("failed to request webfinger")
	}

	response := webfingerPointer.Response()

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid http state code. expected: %v, actual: %v", http.StatusOK, response.StatusCode)
	}

	if response.Status != "200 OK" {
		t.Errorf("invalid http state. expected: 200 OK, actual: %v", response.Status)
	}

	if response.Subject != "acct:joe@example.com" {
		t.Errorf("invalid subject. expected: acct:joe@example.com, actual: %v", response.Subject)
	}

	data := []interface{}{
		map[string]string{
			"rel":  "http://openid.net/specs/connect/1.0/issuer",
			"href": "https://op.example.com",
		},
	}

	for key, value := range data {

		expected := value.(map[string]string)

		if response.Links[key].Rel != expected["rel"] {
			t.Errorf("invalid rel. expected: %v, actual: %v", expected["rel"], response.Links[key].Rel)
		}

		if response.Links[key].Href != expected["href"] {
			t.Errorf("invalid href. expected: %v, actual: %v", expected["href"], response.Links[key].Href)
		}
	}
}

func TestNewWebfingerURLSyntaxSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/.well-known/webfinger").
		MatchParam("resource", "https://example.com/joe").
		MatchParam("rel", "http://openid.net/specs/connect/1.0/issuer").
		Reply(200).
		JSON(map[string]interface{}{
			"subject": "https://example.com/joe",
			"links": []interface{}{
				map[string]string{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": "https://op.example.com",
				},
			},
		})

	webfingerPointer := NewWebfinger(
		"op.example.com",
		URL("https://example.com/joe"),
	)
	if err := webfingerPointer.Request(); err != nil {
		log.Println("failed to request webfinger")
	}

	response := webfingerPointer.Response()

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid http state code. expected: %v, actual: %v", http.StatusOK, response.StatusCode)
	}

	if response.Status != "200 OK" {
		t.Errorf("invalid http state. expected: 200 OK, actual: %v", response.Status)
	}

	if response.Subject != "https://example.com/joe" {
		t.Errorf("invalid subject. expected: https://example.com/joe, actual: %v", response.Subject)
	}

	data := []interface{}{
		map[string]string{
			"rel":  "http://openid.net/specs/connect/1.0/issuer",
			"href": "https://op.example.com",
		},
	}

	for key, value := range data {

		expected := value.(map[string]string)

		if response.Links[key].Rel != expected["rel"] {
			t.Errorf("invalid rel. expected: %v, actual: %v", expected["rel"], response.Links[key].Rel)
		}

		if response.Links[key].Href != expected["href"] {
			t.Errorf("invalid href. expected: %v, actual: %v", expected["href"], response.Links[key].Href)
		}
	}
}

func TestNewWebfingerHostnameAndPortSyntaxSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/.well-known/webfinger").
		MatchParam("resource", "https://op.example.com:8080").
		MatchParam("rel", "http://openid.net/specs/connect/1.0/issuer").
		Reply(200).
		JSON(map[string]interface{}{
			"subject": "https://op.example.com:8080",
			"links": []interface{}{
				map[string]string{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": "https://op.example.com:8080",
				},
			},
		})

	webfingerPointer := NewWebfinger(
		"op.example.com",
		HostnameAndPort("op.example.com", "8080"),
	)
	if err := webfingerPointer.Request(); err != nil {
		log.Println("failed to request webfinger")
	}

	response := webfingerPointer.Response()

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid http state code. expected: %v, actual: %v", http.StatusOK, response.StatusCode)
	}

	if response.Status != "200 OK" {
		t.Errorf("invalid http state. expected: 200 OK, actual: %v", response.Status)
	}

	if response.Subject != "https://op.example.com:8080" {
		t.Errorf("invalid subject. expected: https://example.com:8080, actual: %v", response.Subject)
	}

	data := []interface{}{
		map[string]string{
			"rel":  "http://openid.net/specs/connect/1.0/issuer",
			"href": "https://op.example.com:8080",
		},
	}

	for key, value := range data {

		expected := value.(map[string]string)

		if response.Links[key].Rel != expected["rel"] {
			t.Errorf("invalid rel. expected: %v, actual: %v", expected["rel"], response.Links[key].Rel)
		}

		if response.Links[key].Href != expected["href"] {
			t.Errorf("invalid href. expected: %v, actual: %v", expected["href"], response.Links[key].Href)
		}
	}
}

func TestNewWebfingerAcctURISyntaxSuccess(t *testing.T) {

	defer gock.Off()

	gock.New("https://op.example.com").
		Get("/.well-known/webfinger").
		MatchParam("resource", "acct:juliet%40capulet.example@shopping.example.com").
		MatchParam("rel", "http://openid.net/specs/connect/1.0/issuer").
		Reply(200).
		JSON(map[string]interface{}{
			"subject": "acct:juliet%40capulet.example@shopping.example.com",
			"links": []interface{}{
				map[string]string{
					"rel":  "http://openid.net/specs/connect/1.0/issuer",
					"href": "https://op.example.com",
				},
			},
		})

	webfingerPointer := NewWebfinger(
		"op.example.com",
		AcctURI("juliet@capulet.example", "shopping.example.com"),
	)
	if err := webfingerPointer.Request(); err != nil {
		log.Println("failed to request webfinger")
	}

	response := webfingerPointer.Response()

	if response.StatusCode != http.StatusOK {
		t.Errorf("invalid http state code. expected: %v, actual: %v", http.StatusOK, response.StatusCode)
	}

	if response.Status != "200 OK" {
		t.Errorf("invalid http state. expected: 200 OK, actual: %v", response.Status)
	}

	if response.Subject != "acct:juliet%40capulet.example@shopping.example.com" {
		t.Errorf("invalid subject. expected: acct:juliet%%40capulet.example@shopping.example.com, actual: %v", response.Subject)
	}

	data := []interface{}{
		map[string]string{
			"rel":  "http://openid.net/specs/connect/1.0/issuer",
			"href": "https://op.example.com",
		},
	}

	for key, value := range data {

		expected := value.(map[string]string)

		if response.Links[key].Rel != expected["rel"] {
			t.Errorf("invalid rel. expected: %v, actual: %v", expected["rel"], response.Links[key].Rel)
		}

		if response.Links[key].Href != expected["href"] {
			t.Errorf("invalid href. expected: %v, actual: %v", expected["href"], response.Links[key].Href)
		}
	}
}
