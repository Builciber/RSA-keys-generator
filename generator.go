package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

func GenerateRSAKeyPair(privKeyBitSize int) (*rsa.PrivateKey, error) {
	if privKeyBitSize == 0 {
		return nil, errors.New("private key size cannot be zero")
	}
	pk, err := rsa.GenerateKey(rand.Reader, privKeyBitSize)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func ExportRSAPrivateKeyAsPEMFile(privKey *rsa.PrivateKey, toFile string) error {
	if toFile == "" {
		return errors.New("filename cannot be empty")
	}
	slice := strings.Split(toFile, ".")
	if slice[len(slice)-1] != "pem" {
		return errors.New("expected .pem file extension")
	}
	blockPtr := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	pemBytes := pem.EncodeToMemory(blockPtr)
	if pemBytes == nil {
		return errors.New("error encoding into PEM")
	}
	err := os.WriteFile(toFile, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}

func ParseRSAPrivateKeyFromPEMFile(filename string) (*rsa.PrivateKey, error) {
	if filename == "" {
		return nil, errors.New("filename cannot be empty")
	}
	slice := strings.Split(filename, ".")
	if slice[len(slice)-1] != "pem" {
		return nil, errors.New("expected .pem file extension")
	}
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	blockPtr, _ := pem.Decode(bytes)
	if blockPtr == nil || blockPtr.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("wrong PEM file, private key is mising")
	}
	pk, err := x509.ParsePKCS1PrivateKey(blockPtr.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func ExportRSAPublicKeyAsPEMFile(pubKey *rsa.PublicKey, toFile string) error {
	if toFile == "" {
		return errors.New("filename cannot be empty")
	}
	slice := strings.Split(toFile, ".")
	if slice[len(slice)-1] != "pem" {
		return errors.New("expected .pem file extension")
	}
	blockPtr := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	}
	pemBytes := pem.EncodeToMemory(blockPtr)
	if pemBytes == nil {
		return errors.New("error encoding into PEM")
	}
	err := os.WriteFile(toFile, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}

func ParseRSAPublicKeyKeyFromPEMFile(filename string) (*rsa.PublicKey, error) {
	if filename == "" {
		return nil, errors.New("filename cannot be empty")
	}
	slice := strings.Split(filename, ".")
	if slice[len(slice)-1] != "pem" {
		return nil, errors.New("expected .pem file extension")
	}
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	blockPtr, _ := pem.Decode(bytes)
	if blockPtr == nil || blockPtr.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("wrong PEM file, public key is mising")
	}
	pk, err := x509.ParsePKCS1PublicKey(blockPtr.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
