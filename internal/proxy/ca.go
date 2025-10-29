package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertificateAuthority struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func NewCertificateAuthority() (*CertificateAuthority, error) {
	publicDir := getLeashPublicDir()
	privateDir, err := getLeashPrivateDir()
	if err != nil {
		return nil, err
	}

	certPath := filepath.Join(publicDir, "ca-cert.pem")
	keyPath := filepath.Join(privateDir, "ca-key.pem")

	certInfo, certErr := os.Stat(certPath)
	keyInfo, keyErr := os.Stat(keyPath)

	if certErr == nil && !certInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("CA certificate %s must be a regular file", certPath)
	}
	if keyErr == nil && !keyInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("CA key %s must be a regular file", keyPath)
	}

	switch {
	case certErr == nil && keyErr == nil:
		ca, err := loadCA(certPath, keyPath)
		if err == nil {
			log.Printf("event=ca.restore public_dir=%s private_dir=%s", publicDir, privateDir)
		}
		return ca, err
	case certErr == nil && errors.Is(keyErr, fs.ErrNotExist):
		legacyKey := filepath.Join(publicDir, "ca-key.pem")
		if _, err := os.Stat(legacyKey); err == nil {
			return nil, fmt.Errorf("incomplete certificate authority state: found certificate at %s but private key remains at %s; move it to %s", certPath, legacyKey, keyPath)
		}
		return nil, fmt.Errorf("incomplete certificate authority state: found certificate at %s but missing key at %s", certPath, keyPath)
	case errors.Is(certErr, fs.ErrNotExist) && keyErr == nil:
		return nil, fmt.Errorf("incomplete certificate authority state: found key at %s but missing certificate at %s", keyPath, certPath)
	case certErr != nil && !errors.Is(certErr, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to stat CA certificate: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to stat CA key: %w", keyErr)
	}

	// Generate new CA
	ca, err := generateCA(publicDir, privateDir)
	if err == nil {
		log.Printf("event=ca.generate public_dir=%s private_dir=%s", publicDir, privateDir)
	}
	return ca, err
}

func generateCA(publicDir, privateDir string) (*CertificateAuthority, error) {
	// Generate RSA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"MITM Proxy CA"},
			Country:       []string{"US"},
			Province:      []string{"California"},    // Currently empty
			Locality:      []string{"San Francisco"}, // Currently empty
			StreetAddress: []string{},                // Can remain empty
			PostalCode:    []string{},                // Can remain empty
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Don't allow intermediate CAs
		MaxPathLenZero:        true,
	}

	// Generate certificate
	caCertDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&caKey.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Ensure directory exists
	if err := ensureDir(publicDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to prepare public dir: %w", err)
	}
	if err := ensureDir(privateDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to prepare private dir: %w", err)
	}

	certData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
	if certData == nil {
		return nil, fmt.Errorf("failed to encode CA certificate")
	}

	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})
	if keyData == nil {
		return nil, fmt.Errorf("failed to encode CA key")
	}

	if err := writeFileAtomic(filepath.Join(publicDir, "ca-cert.pem"), certData, 0o644); err != nil {
		return nil, fmt.Errorf("failed to persist CA certificate: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(privateDir, "ca-key.pem"), keyData, 0o600); err != nil {
		return nil, fmt.Errorf("failed to persist CA key: %w", err)
	}

	return &CertificateAuthority{
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

func loadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	// Load CA certificate
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat CA certificate: %w", err)
	}
	if !certInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("CA certificate %s must be a regular file", certPath)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	info, err := os.Stat(keyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			publicKeyPath := filepath.Join(filepath.Dir(certPath), "ca-key.pem")
			if _, pubErr := os.Stat(publicKeyPath); pubErr == nil {
				return nil, fmt.Errorf("failed to stat CA key: expected key at %s but found %s; move the key into the private directory", keyPath, publicKeyPath)
			}
		}
		return nil, fmt.Errorf("failed to stat CA key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("CA key %s must be a regular file", keyPath)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("invalid permission on CA key %s: got %o, want 600", keyPath, info.Mode().Perm())
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return &CertificateAuthority{
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

func (ca *CertificateAuthority) GenerateCertificate(host string) (*tls.Certificate, error) {
	// Generate new key for this certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"MITM Proxy"},
			Country:      []string{"US"},
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add SANs - THIS IS THE CRITICAL PART - must match the hostname
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		// Always add the exact hostname first
		template.DNSNames = []string{host}
		// Add wildcard for subdomains if it's a domain (not an IP)
		if !strings.HasPrefix(host, "*.") && strings.Contains(host, ".") {
			template.DNSNames = append(template.DNSNames, "*."+host)
		}
	}

	// Generate certificate signed by CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.caCert,
		&key.PublicKey,
		ca.caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.caCert.Raw},
		PrivateKey:  key,
	}

	return cert, nil
}

func ensureDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "ca-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// getLeashPublicDir returns the directory where Leash persists public assets.
// Defaults to "/leash" if LEASH_DIR is not set.
func getLeashPublicDir() string {
	if v := os.Getenv("LEASH_DIR"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/leash"
}

// getLeashPrivateDir returns the directory that holds Leash private assets.
// LEASH_PRIVATE_DIR must be set by the runtime.
func getLeashPrivateDir() (string, error) {
	if v := os.Getenv("LEASH_PRIVATE_DIR"); strings.TrimSpace(v) != "" {
		return v, nil
	}
	return "", fmt.Errorf("LEASH_PRIVATE_DIR environment variable is required")
}
