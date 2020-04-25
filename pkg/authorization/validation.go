package authorization

import "strings"

func contains(src string, arr []string) bool {
	for _, value := range arr {
		if src == value {
			return true
		}
	}
	return false
}

func validateResponseType(responseTypes []string, responseTypesSupported []string) bool {
	exacted := false
	for _, supportedTypesString := range responseTypesSupported {
		supportedResponseTypes := strings.Split(supportedTypesString, " ")

		if len(responseTypes) != len(supportedResponseTypes) {
			continue
		}

		contain := false
		for _, responseType := range responseTypes {
			if contains(responseType, supportedResponseTypes) {
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
		if contains(scope, scopesSupported) {
			continue
		} else {
			return false
		}
	}

	return true
}
