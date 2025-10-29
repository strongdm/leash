package proxy

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var envMu sync.Mutex

func TestNewCertificateAuthorityCreatesSplitFiles(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	if ca == nil {
		t.Fatal("expected populated CertificateAuthority, got nil")
	}

	certPath := filepath.Join(publicDir, "ca-cert.pem")
	keyPathPublic := filepath.Join(publicDir, "ca-key.pem")
	keyPathPrivate := filepath.Join(privateDir, "ca-key.pem")

	if _, err := os.Stat(keyPathPublic); !os.IsNotExist(err) {
		t.Fatalf("expected no key in public dir; stat error=%v", err)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("unexpected cert permissions: %o", certInfo.Mode().Perm())
	}
	keyInfo, err := os.Stat(keyPathPrivate)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected key permissions: %o", keyInfo.Mode().Perm())
	}

	initialCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	initialKey, err := os.ReadFile(keyPathPrivate)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	caAgain, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	if caAgain == nil {
		t.Fatal("expected populated CertificateAuthority on reload, got nil")
	}
	reloadedCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read reloaded cert: %v", err)
	}
	reloadedKey, err := os.ReadFile(keyPathPrivate)
	if err != nil {
		t.Fatalf("read reloaded key: %v", err)
	}
	if !bytes.Equal(initialCert, reloadedCert) {
		t.Fatal("certificate regenerated; expected reuse of stored bytes")
	}
	if !bytes.Equal(initialKey, reloadedKey) {
		t.Fatal("private key regenerated; expected reuse of stored bytes")
	}
}

func TestNewCertificateAuthorityRequiresPrivateDir(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	prepareLeashEnv(t, publicDir, "")
	_ = os.Unsetenv("LEASH_PRIVATE_DIR")

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "LEASH_PRIVATE_DIR") {
		t.Fatalf("expected failure when LEASH_PRIVATE_DIR unset, got %v", err)
	}
}

func TestNewCertificateAuthorityEnforcesKeyPermissions(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	if _, err := NewCertificateAuthority(); err != nil {
		t.Fatalf("initial CA create failed: %v", err)
	}
	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod key: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("expected permission failure when key is world-readable, got %v", err)
	}
}

func TestNewCertificateAuthorityFailsWhenKeyInPublicDir(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	if _, err := NewCertificateAuthority(); err != nil {
		t.Fatalf("initial CA create failed: %v", err)
	}

	privateKeyPath := filepath.Join(privateDir, "ca-key.pem")
	publicKeyPath := filepath.Join(publicDir, "ca-key.pem")
	if err := os.Rename(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("failed moving key to public dir: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "move it to") {
		t.Fatalf("expected misplacement failure, got: %v", err)
	}
}

func TestNewCertificateAuthorityRejectsDirectoryKey(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	keyDir := filepath.Join(privateDir, "ca-key.pem")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("expected regular file error, got %v", err)
	}
}

func TestNewCertificateAuthorityRejectsDirectoryCert(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	certDir := filepath.Join(publicDir, "ca-cert.pem")
	if err := os.Mkdir(certDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("expected regular file error, got %v", err)
	}
}

func prepareLeashEnv(t *testing.T, publicDir, privateDir string) {
	t.Helper()

	envMu.Lock()
	t.Cleanup(func() {
		if privateDir != "" {
			if err := os.Unsetenv("LEASH_PRIVATE_DIR"); err != nil {
				t.Errorf("unset LEASH_PRIVATE_DIR: %v", err)
			}
		}
		if err := os.Unsetenv("LEASH_DIR"); err != nil {
			t.Errorf("unset LEASH_DIR: %v", err)
		}
		envMu.Unlock()
	})

	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatalf("mkdir public dir: %v", err)
	}
	if err := os.Setenv("LEASH_DIR", publicDir); err != nil {
		t.Fatalf("set LEASH_DIR: %v", err)
	}

	if privateDir != "" {
		if err := os.MkdirAll(privateDir, 0o700); err != nil {
			t.Fatalf("mkdir private dir: %v", err)
		}
		if err := os.Setenv("LEASH_PRIVATE_DIR", privateDir); err != nil {
			t.Fatalf("set LEASH_PRIVATE_DIR: %v", err)
		}
	}
}

func TestNewCertificateAuthorityErrorsWhenOnlyCertExists(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	if _, err := NewCertificateAuthority(); err != nil {
		t.Fatalf("initial CA create failed: %v", err)
	}

	keyPath := filepath.Join(privateDir, "ca-key.pem")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "incomplete certificate authority state") {
		t.Fatalf("expected incomplete state error, got %v", err)
	}
}

func TestNewCertificateAuthorityErrorsWhenOnlyKeyExists(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	if _, err := NewCertificateAuthority(); err != nil {
		t.Fatalf("initial CA create failed: %v", err)
	}

	certPath := filepath.Join(publicDir, "ca-cert.pem")
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove cert: %v", err)
	}

	if _, err := NewCertificateAuthority(); err == nil || !strings.Contains(err.Error(), "incomplete certificate authority state") {
		t.Fatalf("expected incomplete state error, got %v", err)
	}
}

func TestWriteFileAtomicPreservesExistingData(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "value.txt")
	initial := []byte("first")
	if err := writeFileAtomic(path, initial, 0o600); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	if err := writeFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("unexpected content: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected mode: %o", info.Mode().Perm())
	}
}

func TestGeneratedCertificateMatchesStoredData(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	certPath := filepath.Join(publicDir, "ca-cert.pem")
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("failed to decode PEM from stored cert")
	}
	stored, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse stored cert: %v", err)
	}
	issued, err := ca.GenerateCertificate("example.com")
	if err != nil {
		t.Fatalf("issue leaf cert: %v", err)
	}
	if len(issued.Certificate) == 0 {
		t.Fatal("issued certificate missing raw data")
	}
	leaf, err := x509.ParseCertificate(issued.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(stored); err != nil {
		t.Fatalf("leaf not signed by stored CA: %v", err)
	}
}

func TestGenerateCertificateAddsWildcardSAN(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	tlsCert, err := ca.GenerateCertificate("app.internal.example")
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	expected := map[string]struct{}{
		"app.internal.example":   {},
		"*.app.internal.example": {},
	}
	for _, name := range leaf.DNSNames {
		delete(expected, name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing DNS names in SAN: %v", expected)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs, got %v", leaf.IPAddresses)
	}
}

func TestGenerateCertificateForIPOnlyHasIPSAN(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	ip := "192.0.2.10"
	tlsCert, err := ca.GenerateCertificate(ip)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs for IP, got %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != ip {
		t.Fatalf("expected IP SAN %s, got %v", ip, leaf.IPAddresses)
	}
}

func TestGenerateCertificateWithWildcardHost(t *testing.T) {
	t.Parallel()

	publicDir := t.TempDir()
	privateDir := filepath.Join(publicDir, "private")
	prepareLeashEnv(t, publicDir, privateDir)

	ca, err := NewCertificateAuthority()
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	host := "*.example.com"
	tlsCert, err := ca.GenerateCertificate(host)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
		t.Fatalf("expected only %s in SAN, got %v", host, leaf.DNSNames)
	}
}
