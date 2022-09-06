package aesengine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AESEngine is the AES encryption and decryption object. It has no exposed properties.
type AESEngine struct {
	cipher cipher.Block
	Key    []byte
	gcm    cipher.AEAD
	Nonce  []byte
}

// internal
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// New creates a new AESEngine instance
func New() (cr AESEngine, err error) {
	cr.Key, err = generateRandomBytes(32)
	if err != nil {
		return AESEngine{}, err
	}
	cr.cipher, err = aes.NewCipher(cr.Key)
	if err != nil {
		return AESEngine{}, err
	}
	cr.gcm, err = cipher.NewGCM(cr.cipher)
	if err != nil {
		return AESEngine{}, err
	}
	cr.Nonce = make([]byte, cr.gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, cr.Nonce)
	if err != nil {
		return AESEngine{}, err
	}
	return cr, err
}

// NewWithKey creates a new AESEngine instance with pre-defined key and nonce
func NewWithKey(key []byte, nonce []byte) (cr AESEngine, err error) {
	//	if len(key) != 32 {
	//		return AESEngine{}, errors.New("key size must be 32 bytes")
	//	}
	cr.Key = key
	cr.Nonce = nonce
	cr.cipher, err = aes.NewCipher(cr.Key)
	if err != nil {
		return AESEngine{}, err
	}
	cr.gcm, err = cipher.NewGCMWithNonceSize(cr.cipher, len(cr.Nonce))
	if err != nil {
		return AESEngine{}, err
	}
	return cr, err
}

// Encrypt encrypts a byte-array
func (cr AESEngine) Encrypt(input []byte) (output []byte) {
	output = cr.gcm.Seal(cr.Nonce, cr.Nonce, input, nil)
	return output
}

// Decrypt decrypts an AES-encrypted byte-array. The byte-array should contain both the nonce and encrypted content
func (cr AESEngine) Decrypt(input []byte) (output []byte, err error) {
	if len(input) < cr.gcm.NonceSize() {
		return nil, errors.New("malformed byte array")
	}
	nonce, ciphertext := input[:cr.gcm.NonceSize()], input[cr.gcm.NonceSize():]
	output, err = cr.gcm.Open([]byte{}, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return output, nil
}
