package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type CertConfig struct {
	Country    string
	State      string
	Org        string
	CommonName string
	Password   string
	ValidDays  int
}

// CreateSelfSignedCert generates a self-signed certificate and saves it as a PKCS#12 (.p12) file.
func CreateSelfSignedCert(config CertConfig, outputPath string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{config.Country},
			Province:     []string{config.State},
			Organization: []string{config.Org},
			CommonName:   config.CommonName,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, config.ValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	pfxData, err := pkcs12.Modern.Encode(privKey, parsedCert, nil, config.Password)
	if err != nil {
		return fmt.Errorf("encoding PKCS#12: %w", err)
	}

	if err := os.WriteFile(outputPath, pfxData, 0600); err != nil {
		return fmt.Errorf("writing .p12 file: %w", err)
	}

	return nil
}

// LoadP12 loads a PKCS#12 file and returns the private key and certificate.
func LoadP12(path, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading .p12 file: %w", err)
	}

	privKey, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not RSA")
	}

	return rsaKey, cert, nil
}
