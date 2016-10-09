package main

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/zmap/zgrab/ztools/x509"
)

func main() {
	path := os.Args[1]
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("unable to read specified file")
		os.Exit(1)
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		fmt.Println("%", cert.Subject.String())
		fmt.Println(hex.EncodeToString(x509.SHA256Fingerprint(cert.Raw)))
		if err != nil {
			continue
		}
	}
}
