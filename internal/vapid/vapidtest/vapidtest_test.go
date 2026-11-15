package vapidtest_test

import (
	"testing"
	"time"

	"github.com/backplane-labs/backplane-pushgate/internal/vapid"
	"github.com/backplane-labs/backplane-pushgate/internal/vapid/vapidtest"
)

// A sender's header passes VAPID verification for its audience only.
func TestHeader(t *testing.T) {
	t.Parallel()

	s := vapidtest.New(t)
	header := s.Header(t, "https://push.example.com")

	if key, err := vapid.Verify(header, "https://push.example.com", time.Now()); err != nil || key != s.Public {
		t.Fatalf("Verify = %q, %v", key, err)
	}

	if _, err := vapid.Verify(header, "https://other.example", time.Now()); err == nil {
		t.Fatal("another audience accepted")
	}

	if len(s.PrivateKey(t)) != 43 {
		t.Fatalf("private key %q: want 32 bytes base64url", s.PrivateKey(t))
	}
}
