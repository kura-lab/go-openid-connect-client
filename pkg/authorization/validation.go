package authorization

import (
	"strings"

	mystrings "github.com/kura-lab/go-openid-connect-client/pkg/strings"
)

func validateResponseType(responseTypes []string, responseTypesSupported []string) bool {
	exacted := false
	for _, supportedTypesString := range responseTypesSupported {
		supportedResponseTypes := strings.Split(supportedTypesString, " ")

		if len(responseTypes) != len(supportedResponseTypes) {
			continue
		}

		contain := false
		for _, responseType := range responseTypes {
			if mystrings.Contains(responseType, supportedResponseTypes) {
				contain = true
				continue
			} else {
				contain = false
				break
			}
		}
		if contain {
			exacted = true
			break
		}
	}

	return exacted
}

func validateScope(scopes []string, scopesSupported []string) bool {
	for _, scope := range scopes {
		if mystrings.Contains(scope, scopesSupported) {
			continue
		} else {
			return false
		}
	}

	return true
}
