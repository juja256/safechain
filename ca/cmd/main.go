package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

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
			Usage:     "generate root key and certificate",
			ArgsUsage: "[path to directory]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "alg, a",
					Usage: "certificate algorithm; supported values are 'rsa' for PKCS#1 RSA with 2048bit key and 'ecdsa' for X9.62 ECDSA key on curve P256",
					Value: "ecdsa",
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
				//ca.GenerateLocalCA(path, (c.String("alg")))
				fmt.Printf("Generate %s root certificate to `%s`: OK\n", c.String("alg"), path)
				return nil
			},
		},
		cli.Command{
			Name:  "issue",
			Usage: "issue a certificate",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "root, r",
					Usage: "path to ca root folder",
					Value: "root",
				},
				cli.StringFlag{
					Name:  "cn, n",
					Usage: "common name",
				},
			},
			ArgsUsage: "[path to directory]",
			Action: func(c *cli.Context) error {
				root := c.String("root")
				cn := c.String("cn")
				path := c.Args().First()
				if path == "" {
					path = "certs"
				}

				//ca.IssueCert()
				return nil
			},
		},
		cli.Command{
			Name:      "sign",
			Usage:     "sign a file",
			ArgsUsage: "[path to file] [path to key]",
		},
		cli.Command{
			Name:      "verify",
			Usage:     "verify an ES",
			ArgsUsage: "[path to data file] [path to ES file] [path to certificate]",
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err.Error())
	}
}
