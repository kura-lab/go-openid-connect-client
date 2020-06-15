# go-openid-connect-client
OpenID Connect Relying Party Library for Go

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/kura-lab/go-openid-connect-client)
[![Build Status](https://travis-ci.org/kura-lab/go-openid-connect-client.svg?branch=master)](https://travis-ci.org/kura-lab/go-openid-connect-client)
[![Coverage Status](https://coveralls.io/repos/github/kura-lab/go-openid-connect-client/badge.svg?branch=master)](https://coveralls.io/github/kura-lab/go-openid-connect-client?branch=master)
![GitHub](https://img.shields.io/github/license/kura-lab/go-openid-connect-client)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/kura-lab/go-openid-connect-client)

This library aims to be a lightweight OpenID Connect Relying Party library for Go.  
The library is implemented using only the standard packages provided by Go, making it independent of heavy libraries or frameworks.  
Since it is a simple implementation as much as possible, you need to implement processing such as cache and session management, but it provides the minimum necessary functions (e.g., issuing Access Token, ID Token signature verification etc.) for RP of OpenID Connect.  
In addition, it strives to comply with OAuth 2.0 and its extended profiles as well as OpenID Connect.  
First, let's start the application. Then, check the flow of processing with the output log.  

## Specifications

### OpenID Foundation
* [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)
* [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)

### IETF
* [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
* [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
* [OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
* [OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
* [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
