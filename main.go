package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	var keyId string
	flag.StringVar(&keyId, "kid", "", "aws kms key id")
	flag.Parse()

	if len(keyId) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	kms := NewKmsClient(keyId)
	signer := NewKmsSigner(kms)

	serialNumber, err := generateSerialNumber()
	if err != nil {
		log.Fatalf("failed to generate serial number: %v", err)
	}

	date := "2030-12-31T00:00:00.000Z"
	notAfter, err := time.Parse(time.RFC3339, date)
	if err != nil {
		log.Fatalf("failed to parse date")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"KMS Sign Test"},
		},
		DNSNames:              []string{"kms-sign-test.com"},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := signer.CreateCertificate(&template)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}

	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		log.Fatalf("failed to encode to pem format: %v", err)
	}
}
