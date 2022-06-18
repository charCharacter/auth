package configs

import "github.com/caarlos0/env/v6"

type YDB struct {
	//grpc://localhost:2136?database=/local
	DSNString string `env:"AUTH_YDB_CONNECTION_STRING,required"`
	Token     string `env:"AUTH_YDB_CONNECTION_STRING"`
}

func LoadYDB() (*YDB, error) {
	config := &YDB{}

	if err := env.Parse(config); err != nil {
		return nil, err
	}

	return config, nil
}
