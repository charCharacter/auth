package configs

import (
	"time"

	"github.com/caarlos0/env/v6"
)

type JWT struct {
	SecretKey       string        `env:"AUTH_YDB_CONNECTION_STRING,required"`
	Issuer          string        `env:"AUTH_YDB_CONNECTION_STRING,required"`
	ExpirationHours time.Duration `env:"AUTH_YDB_CONNECTION_STRING,required"`
}

func LoadJWT() (*JWT, error) {
	config := &JWT{}

	if err := env.Parse(config); err != nil {
		return nil, err
	}

	return config, nil
}
