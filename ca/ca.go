package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/juja256/x509"

	"golang.org/x/crypto/sha3"
)

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func PublicKey(priv interface{}) interface{} {
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
	priv, err := parseECPrivateKey(keyBlock.Bytes)
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

var (
	oidNamedCurveP160 = asn1.ObjectIdentifier{1, 3, 132, 0, 30}
	oidNamedCurveP192 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve.Params().BitSize {
	case 160:
		return oidNamedCurveP160, true
	case 192:
		return oidNamedCurveP192, true
	case 224:
		return oidNamedCurveP224, true
	case 256:
		return oidNamedCurveP256, true
	case 384:
		return oidNamedCurveP384, true
	case 521:
		return oidNamedCurveP521, true
	}
	return nil, false
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP160):
		return p160()
	case oid.Equal(oidNamedCurveP192):
		return p192()
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// marshalECPrivateKey marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// marshalECPrivateKey marshals an EC private key into ASN.1, DER format.
func marshalCustomECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	return marshalECPrivateKeyWithOID(key, oid)
}

func p160() elliptic.Curve {
	p160 := new(elliptic.CurveParams)
	p160.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
	p160.N, _ = new(big.Int).SetString("100000000000000000000351EE786A818F3A1A16B", 16)
	p160.B, _ = new(big.Int).SetString("B4E134D3FB59EB8BAB57274904664D5AF50388BA", 16)
	p160.Gx, _ = new(big.Int).SetString("52DCB034293A117E1F4FF11B30F7199D3144CE6D", 16)
	p160.Gy, _ = new(big.Int).SetString("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", 16)
	p160.BitSize = 160
	return p160
}

func p192() elliptic.Curve {
	p192 := new(elliptic.CurveParams)
	p192.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
	p192.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
	p192.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
	p192.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
	p192.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
	p192.BitSize = 192
	return p192
}

const ecPrivKeyVersion = 1

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve

	curve = namedCurveFromOID(privKey.NamedCurveOID)

	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

func GenerateKey(fn string, keylen int) interface{} {
	var ec elliptic.Curve
	switch keylen {
	case 160:
		ec = p160()
	case 192:
		ec = p192()
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
		keyDer, err := marshalCustomECPrivateKey(key)
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

	pubk, err := x509.MarshalPKIXPublicKey(PublicKey(key))
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
		rand.Reader, &template, &template, PublicKey(key), key,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}

	ioutil.WriteFile(path.Join(rootPath, "root", "ca.crt"), certDer, os.ModePerm)
	return
}

func (ca *LocalCA) IssueCert(dn pkix.Name, pubk interface{}) {
	cakey := LoadECPrivateKey(path.Join(ca.path, "root", "ca.key"))
	cacert := LoadCertificate(path.Join(ca.path, "root", "ca.crt"))

	sn, err := ioutil.ReadFile(path.Join(ca.path, "serial"))
	if err != nil {
		sn = []byte{0x31}
		ioutil.WriteFile(path.Join(ca.path, "serial"), sn, os.ModePerm)
	}
	s, _ := strconv.Atoi(string(sn))

	filename := string(sn) + ".crt"

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
	ioutil.WriteFile(path.Join(ca.path, "certs", filename), certDer, os.ModePerm)
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
