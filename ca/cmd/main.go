package main

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/juja256/x509"

	"github.com/juja256/safechain/ca"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Copyright = "(c) 2019 - SafeChain"
	app.Email = ""
	app.Author = "Hrubiian Yevhen"
	app.Usage = "safechain minimal CA realization"
	app.Name = "sefe-ca"
	app.Description = "minimal CA realization"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		cli.Command{
			Name:      "root",
			Usage:     "generate CA context",
			ArgsUsage: "[path to ca directory]",
			Flags:     []cli.Flag{},
			Action: func(c *cli.Context) error {
				dir := c.Args().First()
				ca.CreateLocalCA(dir)
				fmt.Printf("Generate CA context to `%s`: OK\n", dir)
				return nil
			},
		},
		cli.Command{
			Name:      "generate",
			Usage:     "generate new key",
			ArgsUsage: "[path to key file]",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "keylen, l",
					Usage: "ecdsa key length",
					Value: 192,
				},
			},
			Action: func(c *cli.Context) error {
				k := c.Args().First()
				if k == "" {
					k = "pem.key"
				}
				ca.GenerateKey(k, c.Int("keylen"))
				return nil
			},
		},
		cli.Command{
			Name:  "issue",
			Usage: "issue a certificate",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "root, r",
					Usage: "path to ca directory",
					Value: "",
				},
				cli.StringFlag{
					Name:  "cn, n",
					Usage: "common name",
				},
			},
			ArgsUsage: "[path to key file]",
			Action: func(c *cli.Context) error {
				dir := c.String("root")
				cn := c.String("cn")
				keyfn := c.Args().First()

				CA := ca.LoadLocalCA(dir)
				if keyfn == "" {
					keyfn = "pem.key"
				}
				var pk interface{}
				if _, err := os.Stat(keyfn); err != nil {
					pk = ca.GenerateKey(keyfn, 192)
				} else {
					pk = ca.LoadECPrivateKey(keyfn)
				}
				pub := ca.PublicKey(pk)
				dn := pkix.Name{
					CommonName: cn,
				}
				CA.IssueCert(dn, pub)
				return nil
			},
		},
		cli.Command{
			Name:  "sign",
			Usage: "sign a file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "path to key",
					Value: "",
				},
			},
			ArgsUsage: "[file to sign]",
			Action: func(c *cli.Context) error {
				filefn := c.Args().Get(0)
				keyfn := c.String("key")
				if _, err := os.Stat(keyfn); err != nil {
					return err
				}
				if _, err := os.Stat(filefn); err != nil {
					return err
				}
				pk := ca.LoadECPrivateKey(keyfn)
				data, err := ioutil.ReadFile(filefn)
				if err != nil {
					return err
				}
				fmt.Println(base64.StdEncoding.EncodeToString(ca.Sign(data, pk)))
				return nil
			},
		},
		cli.Command{
			Name:      "verify",
			Usage:     "verify an ES",
			ArgsUsage: "[signed file] [ES file or base64 string]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "cert, c",
					Usage: "path to certificate",
					Value: "",
				},
			},
			Action: func(c *cli.Context) error {
				filefn := c.Args().Get(0)
				sigfn := c.Args().Get(1)
				certfn := c.String("cert")
				var signature []byte
				if _, err := os.Stat(filefn); err != nil {
					return err
				}
				if _, err := os.Stat(sigfn); err != nil {
					signature, err = base64.StdEncoding.DecodeString(sigfn)
					if err != nil {
						return err
					}
				} else {
					signature, _ = ioutil.ReadFile(sigfn)
				}
				if _, err := os.Stat(certfn); err != nil {
					return err
				}
				data, _ := ioutil.ReadFile(filefn)
				cerder, _ := ioutil.ReadFile(certfn)
				cert, err := x509.ParseCertificate(cerder)

				if err != nil {
					return err
				}
				ok := ca.Verify(signature, data, cert)
				if ok {
					return nil
				}
				return errors.New("Signature is invalid")
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err.Error())
	}
}
