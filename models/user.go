package models

import (
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	UID            string
	Username       string
	HashedPassword string
}

func NewUser(username string, password string) (*User, error) {
	uid, err := uuid.NewUUID()
	if err != nil {
		return nil, fmt.Errorf("cannot hash password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("cannot hash password: %w", err)
	}

	user := &User{
		UID:            uid.String(),
		Username:       username,
		HashedPassword: string(hashedPassword),
	}

	return user, nil
}
