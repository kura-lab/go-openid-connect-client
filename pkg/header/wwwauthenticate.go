package header

import (
	"regexp"
	"strings"
)

// WWWAuthenticate is struct for WWW-Authenticate header.
type WWWAuthenticate struct {
	Realm            string
	Scope            string
	Error            string
	ErrorDescription string
}

// ParseWWWAuthenticateHeader is function to parse WWW-Authenticate Bearer header.
func ParseWWWAuthenticateHeader(header string) map[string]string {

	rep := regexp.MustCompile(`\ABearer `)
	if !rep.MatchString(header) {
		return map[string]string{}
	}

	header = rep.ReplaceAllString(header, "")

	header = strings.NewReplacer(
		"\r\n", "",
		"\r", "",
		"\n", "",
	).Replace(header)

	attributes := strings.Split(header, ",")

	parsed := map[string]string{}
	for _, attribute := range attributes {
		splited := strings.Split(strings.TrimSpace(attribute), "=")
		parsed[splited[0]] = strings.Trim(splited[1], "\"")
	}

	return parsed
}
