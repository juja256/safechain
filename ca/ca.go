package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli"
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

func GenerateLocalCA(path string, alg string) (interface{}, *x509.Certificate) {
	key := GenerateKey("", alg)

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

	certFile, err := os.Create(path + "ca.crt")
	if err != nil {
		log.Fatal("Failed to open file for writing")
	}
	defer certFile.Close()

	certFile.Write(certDer)
	certFile.Sync()
	return key, &template
}

func GenerateCert(pub, priv interface{}, cert_signer *x509.Certificate, cn string, ku x509.KeyUsage, filename string) {
	sn, _ := ioutil.ReadFile("serial")
	s, _ := strconv.Atoi(string(sn))
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(s)),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Sirius Service"},
		},
		KeyUsage:  ku,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
	}
	certDer, err := x509.CreateCertificate(
		rand.Reader, &template, cert_signer, pub, priv,
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s\n", err)
	}

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to open '%s' for writing: %s", filename, err)
	}
	defer func() {
		certFile.Close()
	}()

	pem.Encode(certFile, &certBlock)
	ioutil.WriteFile("serial", []byte(strconv.Itoa(s+1)), 0644)
}

func VerifySignature(b64signature, pemcert string, data []byte) bool {
	derSignature, err := base64.StdEncoding.DecodeString(b64signature)
	if err != nil {
		return false
	}
	sig := ECDSASignature{}
	_, err = asn1.Unmarshal(derSignature, &sig)
	if err != nil {
		fmt.Print(err)
		return false
	}
	hash := sha512.Sum384(data)
	certBlock, rest := pem.Decode([]byte(pemcert))
	if len(rest) > 0 {
		return false
	}
	certObj, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false
	}
	pubKey := certObj.PublicKey.(*ecdsa.PublicKey)
	return ecdsa.Verify(pubKey, hash[:], sig.R, sig.S)
}

func main() {
	/*switch os.Args[1] {
	case "-g":
		if len(os.Args) < 3 {
			log.Fatal("No CN provided!")
		}
		fn := os.Args[2]
		log.Printf("Generating an ECDSA P-384 Private Key to %s.key", fn)
		keyPem, _ := ioutil.ReadFile("sirius.key")
		certPem, _ := ioutil.ReadFile("sirius.crt")
		keyBlock, _ := pem.Decode(keyPem)
		certBlock, _ := pem.Decode(certPem)

		priv, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
		cert, _ := x509.ParseCertificate(certBlock.Bytes)

		ECKey := GenerateECKey(fn + ".key")
		GenerateCert(&ECKey.PublicKey, priv, cert, fn, x509.KeyUsageDigitalSignature, fn+".crt")
	case "-s":
		var key, data string
		if len(os.Args) < 4 {
			log.Fatal("Invalid params!")
		}
		key = os.Args[2]
		data = os.Args[3]
		//cert := "Han Solo.crt"
		//certPem, _ := ioutil.ReadFile(cert)

		log.Printf("Signing %s with key %s", data, key)
		keyPem, err := ioutil.ReadFile(key)
		if err != nil {
			log.Fatal(err)
		}
		dataRaw, err := ioutil.ReadFile(data)
		if err != nil {
			log.Fatal(err)
		}
		keyBlock, _ := pem.Decode(keyPem)
		priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		hash := sha512.Sum384(dataRaw)
		r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
		if err != nil {
			log.Fatal(err)
		}
		sig := ECDSASignature{r, s}
		sigDer, err := asn1.Marshal(sig)
		if err != nil {
			log.Fatal(err)
		}
		sigb64 := base64.StdEncoding.EncodeToString(sigDer)

		fmt.Println(sigb64)
		//fmt.Print(VerifySignature(string(sigb64), string(certPem), dataRaw))
	case "-v":
		certFile := os.Args[2]
		//fmt.Println(certFile)
		signatureFile := os.Args[3]
		dataFile := os.Args[4]
		//sig := ECDSASignature{}
		//keyPem, err := ioutil.ReadFile("Han Solo.key")
		certPem, _ := ioutil.ReadFile(certFile)
		data, _ := ioutil.ReadFile(dataFile)
		signature, _ := ioutil.ReadFile(signatureFile)
		//fmt.Println(certPem)
		//fmt.Println(data)
		//fmt.Println(signature)
		fmt.Print(VerifySignature(string(signature), string(certPem), data))

	}*/
	app := cli.NewApp()

	app.Commands = []cli.Command{
		cli.Command{
			Name:      "install",
			Usage:     "generate and install root certificate to OS and web-browsers",
			ArgsUsage: "[path to ssl context, i.e. writable folder to store key and certificates]",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "gen-only, g",
					Usage: "only generate certificates without installing",
				},
				cli.StringFlag{
					Name:  "alg, a",
					Usage: "certificate algorithm; supported values are 'rsa' for PKCS#1 RSA with 2048bit key and 'ecdsa' for X9.62 ECDSA key on curve P256",
					Value: "ecdsa",
				},
				cli.StringFlag{
					Name:  "user, u",
					Usage: "user name for installation, if not set default user is the current user",
					Value: "",
				},
			},
			Action: func(c *cli.Context) error {
				path := c.Args().First()
				if path == "" {
					return errors.New("`path` not set")
				}
				if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "\\") {
					path = path + "/"
				}
				if !(c.String("alg") == "rsa" || c.String("alg") == "ecdsa") {
					return errors.New("`alg` invalid")
				}
				GenerateSSLKeyPair(path, c.String("alg"))
				fmt.Printf("Generate %s ssl context to `%s`: OK\n", c.String("alg"), path)

				if !c.Bool("gen-only") {
					cert, err := ioutil.ReadFile(path + "ca.crt")
					if err != nil {
						return err
					}
					err = InstallCertificateToSystemTrustedRoot(cert, c.String("user"))
					if err != nil {
						fmt.Printf("Error installing certificate to OS certstore: %s\n", err.Error())
					} else {
						fmt.Printf("Install certificate to OS certstore: OK\n")
					}
					err = InstallCertificateToFirefox(cert, c.String("user"))
					if err != nil {
						fmt.Printf("Error installing certificate to Firefox certstore: %s\n", err.Error())
					} else {
						fmt.Printf("Install certificate to Firefox certstore: OK\n")
					}
				}

				return nil
			},
		},

		cli.Command{
			Name:      "remove",
			Usage:     "remove certificates from OS and browsers",
			ArgsUsage: "[path to ssl context, i.e. folder where root certificate could be found]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "user, u",
					Usage: "user name for installation, if not set default user is the current user",
					Value: "",
				},
			},
			Action: func(c *cli.Context) error {
				path := c.Args().First()
				if path == "" {
					return errors.New("`path` not set")
				}
				if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "\\") {
					path = path + "/"
				}
				cert, err := ioutil.ReadFile(path + "ca.crt")
				if err != nil {
					return err
				}
				err = DeleteCertificateFromSystemTrustedRoot(cert, c.String("user"))
				if err != nil {
					fmt.Printf("Error removing certificate from OS certstore: %s\n", err.Error())
				} else {
					fmt.Printf("Remove certificate from OS certstore: OK\n")
				}
				err = DeleteCertificateFromFirefox(cert, c.String("user"))
				if err != nil {
					fmt.Printf("Error removing certificate from Firefox certstore: %s\n", err.Error())
				} else {
					fmt.Printf("Remove certificate from Firefox certstore: OK\n")
				}
				return nil
			},
		},
	}
	app.Copyright = "(c) 2019 - SafeChain"
	app.Email = ""
	app.Author = "Hrubiian Yevhen"
	app.Usage = "minimal CA realization"
	app.Name = "sefe-ca"
	app.Description = "minimal CA realization"
	app.Version = "1.0.0"

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err.Error())
	}
}
