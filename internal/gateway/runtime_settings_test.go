package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeTLSSettings(t *testing.T) {
	a := &App{}
	c := TLSConfiguration{Mode: "http01", Email: "ops@example.test"}
	if pending, known := a.tlsRestartRequired(c); pending || known {
		t.Fatal("uninitialized runtime reported active")
	}
	a.RecordTLSStartup(c)
	if pending, known := a.tlsRestartRequired(c); pending || !known {
		t.Fatal("startup settings must match")
	}
	saved := c
	saved.Persisted = true
	saved.DNSToken = "unused"
	if pending, _ := a.tlsRestartRequired(saved); pending {
		t.Fatal("no-op save requires restart")
	}
	saved.Email = "new@example.test"
	if pending, _ := a.tlsRestartRequired(saved); !pending {
		t.Fatal("changed email must require restart")
	}
	if pending, _ := a.tlsRestartRequired(c); pending {
		t.Fatal("revert must clear pending state")
	}
	a.RecordTLSStartup(saved)
	if pending, _ := a.tlsRestartRequired(saved); pending {
		t.Fatal("restart must clear pending state")
	}
}

func TestRuntimeCertificateReplacement(t *testing.T) {
	dir := t.TempDir()
	c := TLSConfiguration{Mode: "manual", CertificateFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	for _, path := range []string{c.CertificateFile, c.KeyFile} {
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{}
	a.RecordTLSStartup(c)
	if err := os.WriteFile(c.CertificateFile, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if pending, _ := a.tlsRestartRequired(c); !pending {
		t.Fatal("certificate replacement was not detected")
	}
}

func TestRuntimeOIDCSecretAndNoop(t *testing.T) {
	s := oidcSettings{Issuer: "https://id.example.test", ClientID: "bastion", ClientSecret: "first"}
	original := oidcFingerprint(s)
	s.SecretConfigured, s.RestartRequired = true, true
	if original != oidcFingerprint(s) {
		t.Fatal("response metadata changed fingerprint")
	}
	s.ClientSecret = "second"
	if original == oidcFingerprint(s) {
		t.Fatal("secret change was not detected")
	}
}

func TestOIDCRestartLoadsSavedSettings(t *testing.T) {
	t.Setenv("BASTION_OIDC_ISSUER", "")
	dir := t.TempDir()
	a, err := New(dir, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := a.oidcSettings(context.Background())
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	saved.RoleClaim = "custom_roles"
	if err := a.saveOIDCSettings(context.Background(), saved); err != nil {
		a.Close()
		t.Fatal(err)
	}
	if a.activeOIDC == oidcFingerprint(saved) {
		a.Close()
		t.Fatal("save changed running configuration")
	}
	a.Close()
	restarted, err := New(dir, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	loaded, err := restarted.oidcSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if restarted.activeOIDC != oidcFingerprint(loaded) {
		t.Fatal("restart did not activate persisted settings")
	}
}
