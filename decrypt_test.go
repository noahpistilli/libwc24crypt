package libwc24crypt

import (
	"io/ioutil"
	"testing"
)

func TestDecryption(t *testing.T) {
	input, err := ioutil.ReadFile("csdata.enc")
	if err != nil {
		panic(err)
	}

	key, err := ioutil.ReadFile("wc24pubk.mod")
	if err != nil {
		panic(err)
	}

	output, err := DecryptWC24(input, key)
	if err != nil {
		panic(err)
	}

	ioutil.WriteFile("csdata.dec", output, 0666)
}

func TestEncryption(t *testing.T) {
	input, err := ioutil.ReadFile("file.dec")
	if err != nil {
		panic(err)
	}

	rsaKey, err := ioutil.ReadFile("Private.pem")
	if err != nil {
		panic(err)
	}

	// Nintendo Channel
	// key := []byte{17, 50, 20, 213, 122, 3, 143, 220, 230, 218, 224, 213, 173, 246, 135, 255}
	// iv := []byte{70, 70, 20, 40, 143, 110, 36, 6, 184, 107, 135, 239, 96, 45, 80, 151}

	// TV no Tomo
	key := []byte{55, 216, 138, 225, 204, 194, 4, 24, 208, 63, 103, 123, 117, 180, 131, 42}
	iv := []byte{181, 9, 109, 182, 149, 185, 150, 148, 101, 28, 213, 254, 120, 80, 39, 133}

	output, err := EncryptWC24(input, key, iv, rsaKey)
	if err != nil {
		panic(err)
	}

	ioutil.WriteFile("file.enc", output, 0666)
}
