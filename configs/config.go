package configs

type Config struct {
	Logger *Logger
	YDB    *YDB
	Rest   *Rest
	GRPC   *GRPC
	JWT    *JWT
}

func LoadConfig() (*Config, error) {
	logger, err := LoadLogger()
	if err != nil {
		return nil, err
	}

	ydb, err := LoadYDB()
	if err != nil {
		return nil, err
	}

	rest, err := LoadRest()
	if err != nil {
		return nil, err
	}

	grpc, err := LoadGRPC()
	if err != nil {
		return nil, err
	}

	jwt, err := LoadJWT()
	if err != nil {
		return nil, err
	}

	return &Config{
		YDB:    ydb,
		Logger: logger,
		Rest:   rest,
		GRPC:   grpc,
		JWT:    jwt,
	}, nil
}
