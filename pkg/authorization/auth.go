package authorization

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Constantine27K/crnt-sdk/pkg/token"
	"google.golang.org/grpc/metadata"
)

const (
	header            = "authorization"
	authorizationType = "bearer"
)

type Authorizer interface {
	AuthorizeUser(ctx context.Context) (*token.Payload, error)
	AuthorizeAdmin(ctx context.Context) (*token.Payload, error)
}

type authorizer struct {
	tokenMaker token.Maker
}

func NewAuthorizer(tokenMaker token.Maker) Authorizer {
	return &authorizer{
		tokenMaker: tokenMaker,
	}
}

func (a *authorizer) AuthorizeUser(ctx context.Context) (*token.Payload, error) {
	accessToken, err := retrieveTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	payload, err := a.tokenMaker.VerifyToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token")
	}

	return payload, nil
}

func (a *authorizer) AuthorizeAdmin(ctx context.Context) (*token.Payload, error) {
	accessToken, err := retrieveTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if accessToken != os.Getenv("ADMIN_TOKEN") {
		return nil, fmt.Errorf("invalid admin token")
	}

	return &token.Payload{
		Username:  "admin",
		Role:      "admin",
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(24 * time.Hour),
	}, nil
}

func retrieveTokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata in context")
	}

	headerValues := md.Get(header)
	if len(headerValues) == 0 {
		return "", fmt.Errorf("no authorization header in context")
	}

	headerValue := headerValues[0]
	fields := strings.Fields(headerValue)
	if len(fields) != 2 {
		return "", fmt.Errorf("invalid authorization header format")
	}

	if authType := fields[0]; strings.ToLower(authType) != authorizationType {
		return "", fmt.Errorf("unsupported authorization type: %s", authType)
	}

	accessToken := fields[1]
	if len(accessToken) == 0 {
		return "", fmt.Errorf("empty access token")
	}

	return accessToken, nil
}
