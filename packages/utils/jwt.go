package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"

	"github.com/charCharacter/history/auth/models"
)

type JwtWrapper struct {
	SecretKey       string
	Issuer          string
	ExpirationHours time.Duration
}

type jwtClaims struct {
	jwt.StandardClaims
	UID      string
	Username string
}

func (w *JwtWrapper) GenerateToken(user *models.User) (signedToken string, err error) {

	if err != nil {
		return "", err
	}
	claims := &jwtClaims{
		UID:      user.UID,
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(w.ExpirationHours)).Unix(),
			Issuer:    w.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err = token.SignedString([]byte(w.SecretKey))

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (w *JwtWrapper) ValidateToken(signedToken string) (claims *jwtClaims, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&jwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(w.SecretKey), nil
		},
	)

	if err != nil {
		return
	}

	claims, ok := token.Claims.(*jwtClaims)

	if !ok {
		return nil, errors.New("Couldn't parse claims")
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("JWT is expired")
	}

	return claims, nil

}
