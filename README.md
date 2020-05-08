# go-openid-connect-client
OpenID Connect Relying Party Library for Go

[![Build Status](https://travis-ci.org/kura-lab/go-openid-connect-client.svg?branch=master)](https://travis-ci.org/kura-lab/go-openid-connect-client)
[![Coverage Status](https://coveralls.io/repos/github/kura-lab/go-openid-connect-client/badge.svg?branch=master)](https://coveralls.io/github/kura-lab/go-openid-connect-client?branch=master)
![GitHub](https://img.shields.io/github/license/kura-lab/go-openid-connect-client)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/kura-lab/go-openid-connect-client)

This library aims to be a lightweight OpenID Connect Relying Party library for Go.  
The library is implemented using only the standard packages provided by Go, making it independent of heavy libraries or frameworks.  
Since it is a simple implementation as much as possible, you need to implement processing such as cache and session management, but it provides the minimum necessary functions (e.g., issuing Access Token, ID Token signature verification etc.) for RP of OpenID Connect.  
First, let's start the application. Then, check the flow of processing with the output log.  
