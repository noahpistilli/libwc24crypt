package libwc24crypt

import (
	"io/ioutil"
	"testing"
)

func TestDecryption(t *testing.T) {
	input, err := ioutil.ReadFile("header_encrypted.bin")
	if err != nil {
		panic(err)
	}

	key, err := ioutil.ReadFile("wc24pubk.mod")
	if err != nil {
		panic(err)
	}

	output, err := decryptWC24(input, key)
	if err != nil {
		panic(err)
	}

	ioutil.WriteFile("header_decrypted.bin", output, 0666)
}

func TestEncryption(t *testing.T) {
	input, err := ioutil.ReadFile("header.bin")
	if err != nil {
		panic(err)
	}

	rsaKey, err := ioutil.ReadFile("Private.pem")
	if err != nil {
		panic(err)
	}
  
  // TV no Tomo key. IV can be anything and it will be embeded in the file because of OFB mode
	key := []byte{55, 216, 138, 225, 204, 194, 4, 24, 208, 63, 103, 123, 117, 180, 131, 42}
	iv := []byte{166, 170, 43, 91, 204, 207, 177, 87, 99, 88, 180, 101, 12, 138, 143, 219}

	output, err := encryptWC24(input, key, iv, rsaKey)
	if err != nil {
		panic(err)
	}

	ioutil.WriteFile("header_encrypted.bin", output, 0666)
}
