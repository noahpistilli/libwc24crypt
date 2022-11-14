package libwc24crypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
)

// WC24File represents the header of an encrypted WC24 File
type WC24File struct {
	Magic     [4]byte
	Version   uint32
	Padding   uint32
	CryptType uint8
	Padding1  [35]byte
	IV        [16]byte
	Signature [256]byte
}

func EncryptWC24(contents []byte, key []byte, iv []byte, rsaData []byte) ([]byte, error) {
	// Load the RSA private key
	rsaBlock, _ := pem.Decode(rsaData)

	parsedKey, err := x509.ParsePKCS1PrivateKey(rsaBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Hash our data then sign
	hash := sha1.New()
	_, err = hash.Write(contents)
	if err != nil {
		return nil, err
	}
	contentsHashSum := hash.Sum(nil)

	reader := rand.Reader
	signature, err := rsa.SignPKCS1v15(reader, parsedKey, crypto.SHA1, contentsHashSum)
	if err != nil {
		return nil, err
	}

	// Encrypt our data with AES-128-OFB
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ofb := cipher.NewOFB(block, iv)
	newData := make([]byte, len(contents))
	ofb.XORKeyStream(newData, contents)

	// Now we set up our header then write the file
	header := WC24File{
		Magic:     [4]byte{'W', 'C', '2', '4'},
		Version:   1,
		Padding:   0,
		CryptType: 1,
		Padding1:  [35]byte{},
	}

	copy(header.IV[:], iv)
	copy(header.Signature[:], signature)

	writer := new(bytes.Buffer)
	err = binary.Write(writer, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	// Finally, write encrypted data to the byte buffer
	binary.Write(writer, binary.BigEndian, newData)

	return writer.Bytes(), nil
}
