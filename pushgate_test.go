package pushgate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	sp "github.com/gopherex/schemapb/go/schemapb"

	pushgate "github.com/backplane-labs/backplane-pushgate"
)

// The configuration reflects into the schema the SDK loads it with: a tag
// that does not parse fails here, not at startup.
func TestConfigSchema(t *testing.T) {
	t.Parallel()

	if _, err := sp.ReflectType[pushgate.Config](sp.ID(sp.Namespace("pushgate"), sp.SchemaName("config"), sp.Ver(1, 0, 0))); err != nil {
		t.Fatal(err)
	}
}

// The defaults are the README's.
func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := backplanetest.Config[pushgate.Config](t, map[string]string{
		"PUBLIC_URL": "https://push.example.com", "NATS_URL": "nats://127.0.0.1:4222",
	})

	if cfg.MaxTTL != 672*time.Hour || cfg.Mailbox.MaxPerChannel != 100 || cfg.Mailbox.AckWait != 30*time.Second ||
		cfg.Mailbox.Replicas != 1 || cfg.Subscriptions.MaxPerChannel != 64 || cfg.Subscriptions.IdleExpiry != 2160*time.Hour ||
		cfg.Session.HelloTimeout != 10*time.Second || cfg.Session.Keepalive != 30*time.Second {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		public string
		nats   string
		err    error
	}{
		{name: "https", public: "https://push.example.com", nats: "nats://n:4222"},
		{name: "http with a path", public: "http://127.0.0.1:8080/push", nats: "nats://n:4222"},
		{name: "no scheme", public: "push.example.com", nats: "nats://n:4222", err: pushgate.ErrPublicURL},
		{name: "ftp", public: "ftp://push.example.com", nats: "nats://n:4222", err: pushgate.ErrPublicURL},
		{name: "query", public: "https://push.example.com/?a=1", nats: "nats://n:4222", err: pushgate.ErrPublicURL},
		{name: "empty", public: "", nats: "nats://n:4222", err: pushgate.ErrPublicURL},
		{name: "no nats", public: "https://push.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]string{"PUBLIC_URL": tc.public}
			if tc.nats != "" {
				vars["NATS_URL"] = tc.nats
			}

			_, err := backplanetest.LoadConfig[pushgate.Config](t.Context(), vars)

			switch {
			case tc.nats == "" && err == nil:
				t.Fatal("no NATS accepted")
			case tc.err != nil && !errors.Is(err, tc.err):
				t.Fatalf("err %v, want %v", err, tc.err)
			case tc.err == nil && tc.nats != "" && err != nil:
				t.Fatalf("valid configuration refused: %v", err)
			}
		})
	}
}
