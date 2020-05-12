package main

import (
	"time"

	"github.com/patrickmn/go-cache"
)

var cached *cache.Cache

func init() {
	// create cache of client id and client secret
	cached = cache.New(24*time.Hour, 25*time.Hour)
}
