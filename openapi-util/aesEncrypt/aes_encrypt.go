package aesEncrypt

/*
ref:
https://developer.aliyun.com/article/1055900

https://try8.cn/tool/cipher/aes
*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// AesCbcEncrypt_HexStr AES CBC encrypt
func AesCbcEncrypt_HexStr(plainText string, secretKey string) (cipherText_Hex string, err error) {
	var (
		byKey        = []byte(secretKey)
		byPlainText  []byte
		byCipherText []byte
	)
	byPlainText = []byte(plainText)

	byCipherText, err = AesCbcEncrypt_Bytes(byPlainText, byKey)
	if nil != err {
		return
	}

	cipherText_Hex = hex.EncodeToString(byCipherText)

	return
}

// AesCbcDecrypt_HexStr AES CBC decrypt
func AesCbcDecrypt_HexStr(cipherText_Hex string, secretKey string) (plainText string, err error) {
	var (
		byKey        = []byte(secretKey)
		byPlainText  []byte
		byCipherText []byte
	)

	byCipherText, err = hex.DecodeString(cipherText_Hex)
	if nil != err {
		return
	}

	byPlainText, err = AesCbcDecrypt_Bytes(byCipherText, byKey)
	if nil != err {
		return
	}

	plainText = string(byPlainText)

	return
}

// AesCbcEncrypt_Base64Str AES CBC encrypt
func AesCbcEncrypt_Base64Str(plainText string, secretKey string) (cipherText_Base64 string, err error) {
	var (
		byKey        = []byte(secretKey)
		byPlainText  []byte
		byCipherText []byte
	)
	byPlainText = []byte(plainText)

	byCipherText, err = AesCbcEncrypt_Bytes(byPlainText, byKey)
	if nil != err {
		return
	}

	cipherText_Base64 = base64.StdEncoding.EncodeToString(byCipherText)

	return
}

// AesCbcDecrypt_Base64Str AES CBC decrypt
func AesCbcDecrypt_Base64Str(cipherText_Base64 string, secretKey string) (plainText string, err error) {
	var (
		byKey        = []byte(secretKey)
		byPlainText  []byte
		byCipherText []byte
	)

	byCipherText, err = base64.StdEncoding.DecodeString(cipherText_Base64)
	if nil != err {
		return
	}

	byPlainText, err = AesCbcDecrypt_Bytes(byCipherText, byKey)
	if nil != err {
		return
	}

	plainText = string(byPlainText)

	return
}

// AesCbcEncrypt_Bytes AES CBC encrypt
func AesCbcEncrypt_Bytes(plainText []byte, key []byte) (cipherText []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if nil != err {
		return
	}

	blocksize := block.BlockSize()

	// PKCS7 Padding
	padded := PKCS7Padding(plainText, blocksize)

	blockmode := cipher.NewCBCEncrypter(block, key[:blocksize])

	cipherText = make([]byte, len(padded))
	blockmode.CryptBlocks(cipherText, padded)
	return
}

// AesCbcDecrypt_Bytes AES CBC decrypt
func AesCbcDecrypt_Bytes(cipherText []byte, key []byte) (plainText []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if nil != err {
		return
	}

	blocksize := block.BlockSize()
	blockmode := cipher.NewCBCDecrypter(block, key[:blocksize])

	decrypted := make([]byte, len(cipherText))

	blockmode.CryptBlocks(decrypted, cipherText)

	plainText, err = PKCS7UnPadding(decrypted)
	return
}

/*
PKCS7Padding 填充
*/
func PKCS7Padding(origData []byte, blockSize int) []byte {
	// calc padding size
	padding := blockSize - len(origData)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	/*
		var padtext []byte
		if 0 == padding {
		    // aligned, fill a whole block, every data is blockSize
		    padtext = bytes.Repeat([]byte{byte(blockSize)}, blockSize)
		} else {
		    // unaligned, fill [padding] number of bytes, every data is [padding]
		    padtext = bytes.Repeat([]byte{byte(padding)}, padding)
		}
		https://cloud.tencent.com/developer/article/2062891
	*/

	return append(origData, padtext...)
}

// PKCS7UnPadding 填充的反向操作
func PKCS7UnPadding(src []byte) (dest []byte, err error) {
	length := len(src)

	if 0 == length {
		err = fmt.Errorf("empty data")
		return
	}

	paddingLen := int(src[length-1])
	if paddingLen > length {
		err = fmt.Errorf("padding size[%d] is larger than data length[%d]", paddingLen, length)
		return
	}

	dest = src[:(length - paddingLen)]
	return
}
