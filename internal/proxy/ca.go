package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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
	// Check if CA already exists
	certPath := filepath.Join(getLeashDir(), "ca-cert.pem")
	if _, err := os.Stat(certPath); err == nil {
		ca, err := loadCA()
		if err == nil {
			log.Printf("event=ca.restore dir=%s", getLeashDir())
		}
		return ca, err
	}

	// Generate new CA
	ca, err := generateCA()
	if err == nil {
		log.Printf("event=ca.generate dir=%s", getLeashDir())
	}
	return ca, err
}

func generateCA() (*CertificateAuthority, error) {
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
	if err := os.MkdirAll(getLeashDir(), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create LEASH_DIR: %w", err)
	}

	// Save CA certificate
	certOut, err := os.Create(filepath.Join(getLeashDir(), "ca-cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("failed to create ca-cert.pem: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	}); err != nil {
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Save CA private key
	keyOut, err := os.Create(filepath.Join(getLeashDir(), "ca-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("failed to create ca-key.pem: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	}); err != nil {
		return nil, fmt.Errorf("failed to write CA key: %w", err)
	}

	return &CertificateAuthority{
		caCert: caCert,
		caKey:  caKey,
	}, nil
}

func loadCA() (*CertificateAuthority, error) {
	// Load CA certificate
	certPEM, err := os.ReadFile(filepath.Join(getLeashDir(), "ca-cert.pem"))
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
	keyPEM, err := os.ReadFile(filepath.Join(getLeashDir(), "ca-key.pem"))
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

// getLeashDir returns the directory where Leash persists state (CA, runtime Cedar, etc.).
// Defaults to "/leash" if LEASH_DIR is not set.
func getLeashDir() string {
	if v := os.Getenv("LEASH_DIR"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/leash"
}
