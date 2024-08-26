package main

import (
	"fmt"
	"log"
)

func main() {
	// Generates the RSA keypair and returns thr private key. The public key can be accessed via `privKey.PublicKey`
	privKey, err := GenerateRSAKeyPair(3072)
	if err != nil {
		log.Fatal(err)
	}
	// Writes the private key to `privkey.pem` file. Filename must have .pem file extension. File need not exist
	err = ExportRSAPrivateKeyAsPEMFile(privKey, "privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	pubKey := privKey.PublicKey
	// Writes the public key to `pubkey.pem` file. Filename must have .pem file extension. File need not exist
	err = ExportRSAPublicKeyAsPEMFile(&pubKey, "pubkey.pem")
	if err != nil {
		log.Fatal(err)
	}

	// retrieves the private key from `privkey.pem` and returns it as *rsa.PrivateKey
	derPrivKey, err := ParseRSAPrivateKeyFromPEMFile("privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	if !privKey.Equal(derPrivKey) {
		log.Fatal("Unequal private keys")
	}

	// retrieves the public key from `pubkey.pem` and returns it as *rsa.PublicKey
	derPubKey, err := ParseRSAPublicKeyKeyFromPEMFile("pubkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	if !pubKey.Equal(derPubKey) {
		log.Fatal("Unequal public keys")
	}

	fmt.Println("Everything works!")
}
