package configs

import "github.com/caarlos0/env/v6"

type Logger struct {
	// Level указывает уровень логирования, поддерживает такие уровни логирования:
	// 	"panic",
	//	"fatal",
	//	"error",
	//	"warn" или "warning",
	//	"info",
	//	"debug",
	//	"trace",
	Level string `env:"AUTH_LOG_LEVEL" envDefault:"info"`
}

func LoadLogger() (*Logger, error) {
	config := &Logger{}

	if err := env.Parse(config); err != nil {
		return nil, err
	}

	return config, nil
}
