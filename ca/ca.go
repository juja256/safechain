package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"
)

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func LoadECPrivateKey(fn string) interface{} {
	keyPem, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPem)
	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return priv
}

func LoadCertificate(fn string) *x509.Certificate {
	certBlock, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Fatal(err)
	}
	certObj, err := x509.ParseCertificate(certBlock)
	if err != nil {
		log.Fatal(err)
	}
	return certObj
}

func GenerateKey(fn string, alg string) interface{} {
	if strings.ToLower(alg) == "rsa" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate RSA key: %s\n", err)
		}
		if fn != "" {

			keyBlock := pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			}

			keyFile, err := os.Create(fn)
			if err != nil {
				log.Fatalf("Failed to open %s for writing: %s", fn, err)
			}
			defer func() {
				keyFile.Close()
			}()

			pem.Encode(keyFile, &keyBlock)
		}
		return key
	} else if strings.ToLower(alg) == "ecdsa" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate ECDSA key: %s\n", err)
		}

		if fn != "" {
			keyDer, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				log.Fatalf("Failed to serialize ECDSA key: %s\n", err)
			}

			keyBlock := pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: keyDer,
			}

			keyFile, err := os.Create(fn)
			if err != nil {
				log.Fatalf("Failed to open %s for writing: %s", fn, err)
			}
			defer func() {
				keyFile.Close()
			}()

			pem.Encode(keyFile, &keyBlock)
		}

		return key
	}
	return nil
}

func GenerateLocalCA(rootPath string, alg string) {
	key := GenerateKey(path.Join(rootPath, "ca.key"), alg)

	pubk, err := x509.MarshalPKIXPublicKey(publicKey(key))
	if err != nil {
		log.Fatalf("Failed to marshal PK: %s\n", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	ski := sha1.Sum(pubk)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SafeChain Root CA",
			Organization: []string{"SafeChain"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski[:],
		IsCA:                  true,
		NotBefore:             time.Now().Add(-12 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 5),
		BasicConstraintsValid: true,
	}

	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, &template, publicKey(key), key,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}

	ioutil.WriteFile(path.Join(rootPath, "ca.crt"), certDer, os.ModePerm)
}

func IssueCert(rootPath string, cn string, filename string) {
	///??????///
	key := LoadECPrivateKey(path.Join(rootPath, "ca.key"))
	cert := LoadCertificate(path.Join(rootPath, "ca.crt"))

	sn, err := ioutil.ReadFile(path.Join(rootPath, "serial"))
	if err != nil {
		sn = []byte{0x31}
		ioutil.WriteFile(path.Join(rootPath, "serial"), sn, os.ModePerm)
	}
	s, _ := strconv.Atoi(string(sn))
	pubk, err := x509.MarshalPKIXPublicKey(publicKey(key))
	if err != nil {
		log.Fatalf("Failed to marshal PK: %s\n", err)
	}
	if filename == "" {
		filename = string(sn)
	}
	ski := sha1.Sum(pubk)
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(s)),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"SafeChain"},
		},
		SubjectKeyId: ski[:],
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, cert, publicKey(key), key,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}
	ioutil.WriteFile(filename, certDer, os.ModePerm)
	ioutil.WriteFile(path.Join(rootPath, "serial"), []byte(strconv.Itoa(s+1)), 0644)
}

func Sign(data []byte, priv interface{}) []byte {
	hash := sha3.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		log.Fatal(err)
	}
	sig := ECDSASignature{r, s}
	sigDer, err := asn1.Marshal(sig)
	if err != nil {
		log.Fatal(err)
	}
	return sigDer
}

func Verify(signature []byte, data []byte, cert *x509.Certificate) bool {
	sig := ECDSASignature{}
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		log.Print(err)
		return false
	}
	hash := sha3.Sum256(data)
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	return ecdsa.Verify(pubKey, hash[:], sig.R, sig.S)
}
