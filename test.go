package main

// import (
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"encoding/base64"
// 	"errors"
// 	"fmt"
// 	"io"
// )

// func Decrypt(key []byte, encrypted string) ([]byte, error) {
// 	fmt.Println("encrypted data:", encrypted)
// 	ciphertext, err := base64.RawURLEncoding.DecodeString(encrypted)
// 	if err != nil {
// 		return nil, err
// 	}
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(ciphertext) < aes.BlockSize {
// 		return nil, errors.New("ciphertext too short")
// 	}
// 	iv := ciphertext[:aes.BlockSize]
// 	ciphertext = ciphertext[aes.BlockSize:]
// 	cfb := cipher.NewCFBDecrypter(block, iv)
// 	cfb.XORKeyStream(ciphertext, ciphertext)
// 	return ciphertext, nil
// }

// func Encrypt(key, data []byte) (string, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}
// 	ciphertext := make([]byte, aes.BlockSize+len(data))
// 	iv := ciphertext[:aes.BlockSize]
// 	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
// 		return "", err
// 	}
// 	stream := cipher.NewCFBEncrypter(block, iv)
// 	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
// 	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
// }

// func main() {
// Secret key (must be 32 bytes for AES-256)
// 	key := []byte("32-byte-long-key-1234567890ABCDE") // Replace with your actual secret key

// 	// Plaintext data to encrypt
// 	plaintext := []byte("This is the data to encrypt")

// 	encrypted, err := Encrypt(key, plaintext)
// 	if err != nil {
// 		fmt.Println("Error encrypting data:", err)
// 		return
// 	}

// 	fmt.Println("ecnrypted data:", encrypted)

// 	data, err := Decrypt(key, "onTXYuWVW9xXtkL5z_ry7DE-GxRcBLT3lUcvbuuYCv5661mSmjlykp3odw")
// 	if err != nil {
// 		fmt.Println("Error decrypot data:", err)
// 		return
// 	}

// 	fmt.Printf("decrypted data: %s\n", string(data))
// }
