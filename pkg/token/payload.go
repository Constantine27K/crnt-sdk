package token

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrExpiredToken = fmt.Errorf("token is expired")
	ErrInvalidToken = fmt.Errorf("token is invalid")
)

type Payload struct {
	ID        uuid.UUID `json:"id,omitempty"`
	Username  string    `json:"username,omitempty"`
	Role      string    `json:"role,omitempty"`
	Team      int64     `json:"team,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

func NewPayload(username, role string, team int64, duration time.Duration) (*Payload, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &Payload{
		ID:        id,
		Username:  username,
		Role:      role,
		Team:      team,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}, err
}

func (t *Payload) Valid() error {
	if time.Now().After(t.ExpiredAt) {
		return ErrExpiredToken
	}

	return nil
}
