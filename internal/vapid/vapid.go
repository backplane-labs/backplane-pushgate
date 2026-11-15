// Package vapid checks a sender's VAPID authorization (RFC 8292): an ES256
// JWT for the push service's origin, signed with the key it names.
package vapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/backplane-labs/backplane-pushgate/internal/domain"
)

// Refusals of an authorization: the sender gets 401.
var (
	// ErrMissing: no Authorization header of scheme vapid.
	ErrMissing = errors.New("vapid: Authorization: vapid t=<jwt>, k=<key> is required")
	// ErrInvalid: the token does not hold (signature, audience, expiry,
	// subject).
	ErrInvalid = errors.New("vapid: invalid authorization")
)

// MaxLifetime is how far ahead a token's exp may be (RFC 8292 2).
const MaxLifetime = 24 * time.Hour

// Verify checks header for audience at now: the sender's key, canonical
// (base64url of the uncompressed point), when the token holds.
func Verify(header, audience string, now time.Time) (string, error) {
	token, key, err := parse(header)
	if err != nil {
		return "", err
	}

	canonical, err := domain.ParseKey(key)
	if err != nil {
		return "", fmt.Errorf("%w: k: %w", ErrInvalid, err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(canonical)
	if err != nil {
		return "", fmt.Errorf("%w: k: %w", ErrInvalid, err)
	}

	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return "", fmt.Errorf("%w: k: %w", ErrInvalid, err)
	}

	claims := jwt.MapClaims{}

	_, err = jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return public, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}), jwt.WithAudience(audience),
		jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp.After(now.Add(MaxLifetime)) {
		return "", fmt.Errorf("%w: exp is more than 24 hours ahead", ErrInvalid)
	}

	if sub, _ := claims.GetSubject(); !strings.HasPrefix(sub, "mailto:") && !strings.HasPrefix(sub, "https:") {
		return "", fmt.Errorf("%w: sub must be a mailto: or https: URL", ErrInvalid)
	}

	return canonical, nil
}

// parse splits "vapid t=<jwt>, k=<key>" (parameters in any order).
func parse(header string) (string, string, error) {
	scheme, params, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "vapid") {
		return "", "", ErrMissing
	}

	var token, key string

	for param := range strings.SplitSeq(params, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(param), "=")

		switch strings.ToLower(name) {
		case "t":
			token = value
		case "k":
			key = value
		}
	}

	if token == "" || key == "" {
		return "", "", ErrMissing
	}

	return token, key, nil
}
