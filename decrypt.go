package libwc24crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// DecryptWC24 decrypts a WiiConnect24 file.
func DecryptWC24(contents []byte, key []byte) ([]byte, error) {
	// First we find out if the passed key is an AES key or wc24pubk.mod file.
	switch len(key) {
	case 16:
		// AES Key
		break
	case 544:
		// wc24pubk.mod
		key = key[512:528]
		break
	default:
		err := fmt.Errorf("the supplied key was not 16 bytes or a wc24pubk.mod file")
		return nil, err
	}

	// The IV is located in the encrypted file
	iv := contents[48:64]
	fmt.Println(iv)
	fmt.Println(key)

	// The actual data is located at offset 320
	data := contents[320:]

	// Now we decrypt!
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ofb := cipher.NewOFB(block, iv)
	newData := make([]byte, len(data))
	ofb.XORKeyStream(newData, data)

	return newData, nil
}
