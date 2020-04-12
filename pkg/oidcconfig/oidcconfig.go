package oidcconfig

type OIDCConfig struct {
	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
	jWKsURI               string
}

func NewOIDCConfig(issuer string, options ...Option) *OIDCConfig {
	config := new(OIDCConfig)
	config.issuer = issuer

	for _, option := range options {
		option(config)
	}
	return config
}

type Option func(*OIDCConfig) error

func AuthorizationEndpoint(authorizationEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.authorizationEndpoint = authorizationEndpoint
		return nil
	}
}

func TokenEndpoint(tokenEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.tokenEndpoint = tokenEndpoint
		return nil
	}
}

func UserInfoEndpoint(userInfoEndpoint string) Option {
	return func(config *OIDCConfig) error {
		config.userInfoEndpoint = userInfoEndpoint
		return nil
	}
}

func JWKsURI(jWKsURI string) Option {
	return func(config *OIDCConfig) error {
		config.jWKsURI = jWKsURI
		return nil
	}
}

func (config *OIDCConfig) Issuer() string {
	return config.issuer
}

func (config *OIDCConfig) AuthorizationEndpoint() string {
	return config.authorizationEndpoint
}

func (config *OIDCConfig) TokenEndpoint() string {
	return config.tokenEndpoint
}

func (config *OIDCConfig) UserInfoEndpoint() string {
	return config.userInfoEndpoint
}

func (config *OIDCConfig) JWKsURI() string {
	return config.jWKsURI
}
