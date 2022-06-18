package main

import (
	"context"
	"net"
	"net/http"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/validator"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/charCharacter/history/auth/configs"
	"github.com/charCharacter/history/auth/models"
	"github.com/charCharacter/history/auth/packages/utils"
	pb "github.com/charCharacter/history/auth/pb"
	"github.com/charCharacter/history/auth/repository/ydb"
)

type UserStore interface {
	UserCreate(*models.User) error
	UserFind(username string) (models.User, error)
	Close() error
}

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	JWT  utils.JwtWrapper
	repo UserStore
}

func NewAuthServer(repo UserStore, jwt utils.JwtWrapper) (*AuthServer, error) {

	return &AuthServer{
		repo: repo,
		JWT:  jwt,
	}, nil
}

func (s *AuthServer) AuthRegister(ctx context.Context, in *pb.AuthRegisterRequest) (*pb.AuthRegisterResponse, error) {
	user, err := models.NewUser(in.Username, in.Password)
	if err != nil {
		return nil, err
	}
	err = s.repo.UserCreate(user)
	if err != nil {
		return nil, err
	}
	return &pb.AuthRegisterResponse{
		Uid: user.UID,
	}, nil
}

type LoginError string

func (err LoginError) Error() string {
	return string(err)
}

func (s *AuthServer) AuthLogin(ctx context.Context, in *pb.AuthLoginRequest) (*pb.AuthLoginResponse, error) {
	user, err := s.repo.UserFind(in.Username)
	log.Infoln(user.Username)
	if err != nil {
		return nil, err
	}

	match := utils.CheckPasswordHash(in.Password, user.HashedPassword)

	if !match {
		return nil, LoginError("Password don't match")
	}

	token, err := s.JWT.GenerateToken(&user)
	if err != nil {
		return nil, err
	}

	return &pb.AuthLoginResponse{
		Token:    token,
		Username: user.Username,
	}, nil
}

func (s *AuthServer) AuthValidate(ctx context.Context, in *pb.AuthValidateRequest) (*pb.AuthValidateResponse, error) {

	claims, err := s.JWT.ValidateToken(in.Token)

	if err != nil {
		return nil, err
	}

	user, err := s.repo.UserFind(claims.Username)

	if err != nil {
		return nil, err
	}

	return &pb.AuthValidateResponse{
		Uid: user.UID,
	}, nil
}

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	config, err := configs.LoadConfig()
	if err != nil {
		log.Fatalf("can't load app config with error [%s]", err)
	}
	level, err := log.ParseLevel(config.Logger.Level)
	if err != nil {
		level = log.WarnLevel
	}
	log.SetLevel(level)
	lis, err := net.Listen("tcp", config.GRPC.Address)
	if err != nil {
		log.Fatalf("Failed to listen: [%s]", err)
	}
	db, err := ydb.NewYDB(ctx, config.YDB)
	if err != nil {
		log.Fatalf("Failed to listen: [%s]", err)
	}
	jwt := utils.JwtWrapper{
		SecretKey:       config.JWT.SecretKey,
		Issuer:          config.JWT.Issuer,
		ExpirationHours: config.JWT.ExpirationHours,
	}
	serv, err := NewAuthServer(db, jwt)
	defer func() {
		_ = serv.repo.Close()
	}()
	if err != nil {
		log.Fatalf("Failed to start server: [%s]", err)
	}
	s := grpc.NewServer(
		grpc.ChainStreamInterceptor(
			//auth.StreamServerInterceptor(myAuthFunction),
			recovery.StreamServerInterceptor(),
			validator.StreamServerInterceptor(),
		),
		grpc.ChainUnaryInterceptor(
			//auth.UnaryServerInterceptor(myAuthFunction),
			recovery.UnaryServerInterceptor(),
			validator.UnaryServerInterceptor(),
		),
	)
	pb.RegisterAuthServiceServer(s, serv)
	log.Infoln("Serving gRPC on ", config.GRPC.Address)
	go func() {
		log.Fatalln(s.Serve(lis))
	}()

	conn, err := grpc.DialContext(
		context.Background(),
		config.GRPC.Address,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to dial server: [%s]", err)
	}

	gwmux := runtime.NewServeMux()
	err = pb.RegisterAuthServiceHandler(context.Background(), gwmux, conn)

	if err != nil {
		log.Fatalf("Failed to register gateway: [%s]", err)
	}

	gwServer := &http.Server{
		Addr:        config.Rest.Address,
		Handler:     gwmux,
		ReadTimeout: config.Rest.Timeout,
	}
	log.Infoln("Serving gRPC-Gateway on ", config.Rest.Address)
	log.Fatalln(gwServer.ListenAndServe())

}
