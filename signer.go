package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// KmsSigner implements crypto.Signer interface
type KmsSigner struct {
	kmsClient *KmsClient
}

func (s *KmsSigner) Public() crypto.PublicKey {
	key, _ := s.kmsClient.PublicKey()
	publicKey, _ := x509.ParsePKIXPublicKey(key)
	return publicKey
}

func (s *KmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("only cryto.SHA256 supported")
	}

	return s.kmsClient.Sign(digest)
}

func (s *KmsSigner) CreateCertificate(template *x509.Certificate) (cert []byte, err error) {
	derEncodedPublicKey, err := s.kmsClient.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(derEncodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %w", err)
	}

	subjectKeyId, err := generateSubjectKeyId(derEncodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to compuate subject key identifier: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate serial number")
	}

	template.SignatureAlgorithm = x509.SHA256WithRSA
	template.SubjectKeyId = subjectKeyId
	template.SerialNumber = serialNumber

	return x509.CreateCertificate(rand.Reader, template, template, publicKey, s)
}

func NewKmsSigner(kmsClient *KmsClient) KmsSigner {
	return KmsSigner{
		kmsClient: kmsClient,
	}
}

func generateSubjectKeyId(derEncodedPublicKey []byte) ([]byte, error) {
	asn1PublicKey := struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{}

	if _, err := asn1.Unmarshal(derEncodedPublicKey, &asn1PublicKey); err != nil {
		return nil, err
	}

	subjectKeyId := sha1.Sum(asn1PublicKey.SubjectPublicKey.Bytes)
	return subjectKeyId[:], nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
