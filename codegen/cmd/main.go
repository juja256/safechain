package main

import (
	"fmt"
	"image/png"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/juja256/x509"

	"github.com/boombuler/barcode/qr"
	"github.com/juja256/safechain/ca"
	"github.com/juja256/safechain/codegen"
)

func main() {
	pi := codegen.NewPillInfo(1, 1, time.Now())
	key := ca.LoadECPrivateKey("../../ca/cmd/160.key")
	pi.Sign(key)
	fmt.Println(key.Curve.Params().BitSize)
	im, err := pi.GenerateCode(200, qr.L)
	if err != nil {
		log.Fatal(err)
	}
	w, err := os.Create("code.png")
	if err != nil {
		log.Fatal(err)
	}
	err = png.Encode(w, im)
	if err != nil {
		log.Fatal(err)
	}
	encoded := pi.Encode(true)
	pi2, err := codegen.DecodePillInfo(encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pi)
	fmt.Println(pi2)
	cf, _ := ioutil.ReadFile("../../ca/cmd/certs/7.crt")
	cert, err := x509.ParseCertificate(cf)
	if err != nil {
		log.Fatal(err)
	}
	err = pi2.Verify(cert)
	fmt.Println(err)
}
