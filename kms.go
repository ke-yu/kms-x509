package main

import (
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var (
	kmsOnce sync.Once
	kmsSvc  *kms.KMS
)

type KmsClient struct {
	keyId string
	svc   *kms.KMS
}

// New a KMS client. Only support RSASSA_PKCS1_V1_5_SHA_256 algorithm.
func NewKmsClient(keyId string) *KmsClient {
	kmsOnce.Do(func() {
		sess := session.Must(session.NewSession(&aws.Config{
			Region: aws.String("us-east-1"),
		}))

		kmsSvc = kms.New(sess)
	})

	return &KmsClient{
		keyId: keyId,
		svc:   kmsSvc,
	}
}

func (c *KmsClient) PublicKey() ([]byte, error) {
	publickKey, err := c.svc.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: aws.String(c.keyId),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return publickKey.PublicKey, err
}

func (c *KmsClient) Sign(digest []byte) ([]byte, error) {
	signed, err := c.svc.Sign(&kms.SignInput{
		KeyId:            aws.String(c.keyId),
		Message:          digest,
		SigningAlgorithm: aws.String("RSASSA_PKCS1_V1_5_SHA_256"),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to sign the message: %w", err)
	}

	return signed.Signature, nil
}
