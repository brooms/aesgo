package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

var key []byte
var block cipher.Block

// AesEncrypt based on operation will either encrypt or decrypt the bytes using the password and iv the initialisation vector using
// AES-128
func AesEncrypt(bytes []byte, operation bool, password string, iv []byte) ([]byte, error) {

	if key == nil {
		var err error
		key, err = ConstructKey(password)
		check(err)

		block, err = aes.NewCipher(key)
		check(err)
	}

	switch operation {
	case true:
		return decrypt(bytes, password, iv)
	default:
		return encrypt(bytes, password, iv)
	}
}

func decrypt(bytes []byte, password string, iv []byte) ([]byte, error) {

	if len(bytes) < aes.BlockSize {
		panic("Ciphertext too short, must be at least 16 bytes in length")
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	plaintext := make([]byte, len(bytes))
	stream.XORKeyStream(plaintext, bytes)

	return plaintext, nil
}

func encrypt(bytes []byte, password string, iv []byte) ([]byte, error) {

	ciphertext := make([]byte, len(bytes))

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, bytes)

	return ciphertext, nil
}

// GenerateInitVec will generate a valid, random AES-128 initialisation vector
func GenerateInitVec() []byte {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	return iv
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
