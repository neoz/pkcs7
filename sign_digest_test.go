package pkcs7

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"strings"
	"testing"
)

func TestNewSignedDataFromDigest_MatchesContent(t *testing.T) {
	content := []byte("hello pdf")
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)

	fromContent, err := NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	fromDigest := NewSignedDataFromDigest(digest[:])

	var messageDigests [][]byte
	for _, sd := range []*SignedData{fromContent, fromDigest} {
		sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
		if err := sd.AddSignerChain(cert.Certificate, *cert.PrivateKey, nil, SignerInfoConfig{SkipSigningTime: true}); err != nil {
			t.Fatalf("AddSignerChain: %v", err)
		}
		sd.Detach()
		der, err := sd.Finish()
		if err != nil {
			t.Fatalf("Finish: %v", err)
		}
		p7, err := Parse(der)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		p7.Content = content
		if err := p7.Verify(); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		var md []byte
		if err := p7.UnmarshalSignedAttribute(OIDAttributeMessageDigest, &md); err != nil {
			t.Fatalf("messageDigest attribute: %v", err)
		}
		messageDigests = append(messageDigests, md)
	}
	if !bytes.Equal(messageDigests[0], messageDigests[1]) {
		t.Fatalf("messageDigest mismatch: content %x, digest %x", messageDigests[0], messageDigests[1])
	}
}

func TestNewSignedDataFromDigest_WrongLength(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	sd := NewSignedDataFromDigest(make([]byte, 20))
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	err = sd.AddSignerChain(cert.Certificate, *cert.PrivateKey, nil, SignerInfoConfig{})
	if err == nil || !strings.Contains(err.Error(), "precomputed digest is 20 bytes") {
		t.Fatalf("AddSignerChain error = %v, want precomputed digest length error", err)
	}
}

func TestNewSignedDataFromDigest_MLDSA(t *testing.T) {
	content := []byte("hello ml-dsa")
	for _, test := range mlDSATestCases {
		t.Run(test.name, func(t *testing.T) {
			cert, key := createMLDSATestCertificate(t, test)
			digest := sha512.Sum512(content)
			sd := NewSignedDataFromDigest(digest[:])
			sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA512)
			if err := sd.AddSignerChain(cert, key, nil, SignerInfoConfig{}); err != nil {
				t.Fatalf("AddSignerChain: %v", err)
			}
			der, err := sd.Finish()
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			p7.Content = content
			if err := p7.Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestNewSignedDataFromDigest_SignWithoutAttr(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("x"))
	sd := NewSignedDataFromDigest(digest[:])
	sd.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
	if err := sd.SignWithoutAttr(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err == nil {
		t.Fatal("SignWithoutAttr on a precomputed digest succeeded, want error")
	}
}
