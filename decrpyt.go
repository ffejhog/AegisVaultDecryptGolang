package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

type Slot struct {
	Type       int    `json:"type"`
	Salt       string `json:"salt"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Key        string `json:"key"`
	Key_params struct {
		Nonce string `json:"nonce"`
		Tag   string `json:"tag"`
	} `json:"key_params"`
}

type Header struct {
	Slots  []Slot `json:"slots"`
	Params struct {
		Nonce string `json:"nonce"`
		Tag   string `json:"tag"`
	} `json:"params"`
}

type AegisVault struct {
	Header Header `json:"header"`
	Db     string `json:"db"`
}

func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) < 1 {
		log.Fatal("No input file provided")
	}
	inputFile := argsWithoutProg[0]

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatal(err)
	}

	var vault AegisVault
	err = json.Unmarshal(data, &vault)
	if err != nil {
		log.Fatal(err)
	}

	var masterKey []byte
	for _, slot := range vault.Header.Slots {
		if slot.Type == 1 {
			salt, _ := hex.DecodeString(slot.Salt)
			dk, err := scrypt.Key([]byte("Jeff#739182465"), salt, slot.N, slot.R, slot.P, 32)
			if err != nil {
				log.Fatal(err)
			}

			block, err := aes.NewCipher(dk)
			if err != nil {
				log.Fatal(err)
			}

			nonce, _ := hex.DecodeString(slot.Key_params.Nonce)
			aesgcm, err := cipher.NewGCM(block)
			if err != nil {
				log.Fatal(err)
			}

			key, _ := hex.DecodeString(slot.Key)
			tag, _ := hex.DecodeString(slot.Key_params.Tag)
			ciphertext := append(key, tag...)
			plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
			if err == nil {
				masterKey = plaintext
				break
			}
		}
	}

	if masterKey == nil {
		log.Fatal("error: unable to decrypt the master key with the given password")
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonce, _ := hex.DecodeString(vault.Header.Params.Nonce)
	content, _ := base64.StdEncoding.DecodeString(vault.Db)
	tag, _ := hex.DecodeString(vault.Header.Params.Tag)
	ciphertext := append(content, tag...)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext))
}
