package codegen

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"image"
	"time"

	"github.com/juja256/x509"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/juja256/safechain/ca"
)

func generateCode(rawData []byte, pxsize int, errorCorrectionLevel qr.ErrorCorrectionLevel) (image.Image, error) {
	b64 := base64.StdEncoding.EncodeToString(rawData)
	code, err := qr.Encode(b64, errorCorrectionLevel, qr.Unicode)
	if err != nil {
		return nil, err
	}
	code, err = barcode.Scale(code, pxsize, pxsize)
	return code, err
}

type PillInfo struct {
	ExpDate struct {
		Month uint
		Year  uint
	}
	PillSerialNumber   uint64
	VendorSerialNumber uint32
	VendorSignature    []byte
}

func NewPillInfo(psn uint64, vsn uint32, t time.Time) *PillInfo {
	p := &PillInfo{
		PillSerialNumber:   psn,
		VendorSerialNumber: vsn,
	}
	p.ExpDate.Month = uint(t.Month())
	p.ExpDate.Year = uint(t.Year())
	return p
}

func (p *PillInfo) Encode(withSignature bool) []byte {
	var sigsz int
	if withSignature {
		sigsz = len(p.VendorSignature)
	}
	info := make([]byte, 16+sigsz)
	info[0] = byte('s')
	info[1] = byte(sigsz)
	binary.LittleEndian.PutUint64(info[2:10], p.PillSerialNumber)
	binary.LittleEndian.PutUint32(info[10:14], p.VendorSerialNumber)
	info[14] = byte((p.ExpDate.Month & 0x0F) << 4)
	info[14] |= byte((p.ExpDate.Year & 0xF00) >> 8)
	info[15] = byte((p.ExpDate.Year & 0xFF))
	if withSignature {
		copy(info[16:16+sigsz], p.VendorSignature)
	}

	return info
}

func (p *PillInfo) Sign(pk *ecdsa.PrivateKey) {
	p.VendorSignature = []byte{}
	p.VendorSignature = ca.Sign(p.Encode(false), pk)
}

func (p *PillInfo) GenerateCode(pxsize int, ecl qr.ErrorCorrectionLevel) (image.Image, error) {
	return generateCode(p.Encode(true), pxsize, ecl)
}

func DecodePillInfo(data []byte) (pi *PillInfo, err error) {
	if data[0] != byte('s') || len(data) != 16+int(data[1]) {
		return nil, errors.New("Format is broken")
	}
	pi = new(PillInfo)
	pi.PillSerialNumber = binary.LittleEndian.Uint64(data[2:10])
	pi.VendorSerialNumber = binary.LittleEndian.Uint32(data[10:14])
	pi.ExpDate.Month = uint((data[14] & 0xF0) >> 4)
	pi.ExpDate.Year = (uint(data[14]&0x0F) << 8) + uint(data[15])
	pi.VendorSignature = data[16 : 16+int(data[1])]
	return pi, nil
}

func (p *PillInfo) Verify(c *x509.Certificate) error {
	if ca.Verify(p.VendorSignature, p.Encode(false), c) {
		return nil
	}
	return errors.New("Signature is invalid")
}
