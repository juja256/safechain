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

func GenerateKey(fn string, keylen int) interface{} {
	var ec elliptic.Curve
	switch keylen {
	case 192:
		// PM_NIST_P192
		p192 := new(elliptic.CurveParams)
		p192.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
		p192.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
		p192.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
		p192.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
		p192.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
		p192.BitSize = 192
		ec = p192
	case 224:
		ec = elliptic.P224()
	case 256:
		ec = elliptic.P256()
	case 384:
		ec = elliptic.P384()
	case 521:
		ec = elliptic.P521()
	default:
		ec = elliptic.P256()
	}
	key, err := ecdsa.GenerateKey(ec, rand.Reader)
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

type LocalCA struct {
	path string
}

func CreateLocalCA(rootPath string) (ca *LocalCA) {
	ca = new(LocalCA)
	err := os.MkdirAll(path.Join(rootPath, "root"), os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	err = os.MkdirAll(path.Join(rootPath, "certs"), os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}

	key := GenerateKey(path.Join(rootPath, "root", "ca.key"), 521)
	ca.path = rootPath

	ioutil.WriteFile(path.Join(rootPath, "serial"), []byte{0x31}, os.ModePerm)

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

	ioutil.WriteFile(path.Join(rootPath, "root", "ca.crt"), certDer, os.ModePerm)
	return
}

func (ca *LocalCA) IssueCert(dn pkix.Name, pubk interface{}) {
	cakey := LoadECPrivateKey(path.Join(ca.path, "root", "ca.crt"))
	cacert := LoadCertificate(path.Join(ca.path, "root", "ca.crt"))

	sn, err := ioutil.ReadFile(path.Join(ca.path, "serial"))
	if err != nil {
		sn = []byte{0x31}
		ioutil.WriteFile(path.Join(ca.path, "serial"), sn, os.ModePerm)
	}
	s, _ := strconv.Atoi(string(sn))

	filename := string(sn)

	pubkB, err := x509.MarshalPKIXPublicKey(pubk)
	if err != nil {
		log.Fatalf("Failed to marshal PK: %s\n", err)
	}
	ski := sha1.Sum(pubkB)
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(s)),
		Subject:      dn,
		SubjectKeyId: ski[:],
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, cacert, pubk, cakey,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}
	ioutil.WriteFile(filename, certDer, os.ModePerm)
	ioutil.WriteFile(path.Join(ca.path, "serial"), []byte(strconv.Itoa(s+1)), 0644)
}

func LoadLocalCA(p string) *LocalCA {
	return &LocalCA{p}
}

func (ca *LocalCA) SearchBySN(sn int) *x509.Certificate {
	c, e := ioutil.ReadFile(path.Join(ca.path, "certs", strconv.Itoa(sn)))
	if e != nil {
		return nil
	}
	cert, _ := x509.ParseCertificate(c)
	return cert
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
