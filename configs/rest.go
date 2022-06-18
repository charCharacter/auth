package configs

import (
	"time"

	"github.com/caarlos0/env/v6"
)

type Rest struct {
	Address string `env:"AUTH_REST_ADDRESS,required"`

	Timeout time.Duration `env:"AUTH_REST_TIMEOUT_SECONDS"  envDefault:"30s"`
}

func LoadRest() (*Rest, error) {
	config := &Rest{}

	if err := env.Parse(config); err != nil {
		return nil, err
	}

	return config, nil
}
