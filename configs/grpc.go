package configs

import (
	"github.com/caarlos0/env/v6"
)

type GRPC struct {
	Address string `env:"AUTH_GRPC_ADDRESS,required"`
}

func LoadGRPC() (*GRPC, error) {
	config := &GRPC{}

	if err := env.Parse(config); err != nil {
		return nil, err
	}

	return config, nil
}
