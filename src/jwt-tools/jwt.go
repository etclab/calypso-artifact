package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CoreDNSClaims struct {
	ClientID    string   `json:"client_id"`
	Permissions []string `json:"permissions"`
	AllowedZones []string `json:"allowed_zones,omitempty"`
	jwt.RegisteredClaims
}

func generateJWT(privateKey interface{}, algorithm string, clientID string, permissions []string, allowedZones []string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := CoreDNSClaims{
		ClientID:    clientID,
		Permissions: permissions,
		AllowedZones: allowedZones,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "jwt-tools",
			Subject:   clientID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	var signingMethod jwt.SigningMethod
	switch algorithm {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "EdDSA":
		signingMethod = jwt.SigningMethodEdDSA
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func verifyJWT(publicKey interface{}, tokenString string) (*CoreDNSClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CoreDNSClaims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return publicKey, nil
		case *jwt.SigningMethodECDSA:
			return publicKey, nil
		case *jwt.SigningMethodEd25519:
			return publicKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*CoreDNSClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}