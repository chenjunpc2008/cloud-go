package aesEncrypt

import (
	"encoding/hex"
	"testing"

	"github.com/bmizerany/assert"
)

type padding_tcaseSt struct {
	caseName string

	in_input     []byte
	in_blockSize int

	out_haveError bool
	out_expect    string
}

func Test_PKCS7Padding(t *testing.T) {
	tcases := []padding_tcaseSt{
		{
			caseName:     "padd-01",
			in_input:     []byte("YELLOW SUBMARINE"),
			in_blockSize: 16,
			out_expect:   "59454c4c4f57205355424d4152494e4510101010101010101010101010101010",
		},
		{
			caseName:     "padd-02",
			in_input:     []byte("YELLOW SUBMARINE"),
			in_blockSize: 15,
			out_expect:   "59454c4c4f57205355424d4152494e450e0e0e0e0e0e0e0e0e0e0e0e0e0e",
		},
	}

	t.Helper()

	for _, tc := range tcases {

		t.Run(tc.caseName, func(t *testing.T) {
			resPadd := PKCS7Padding(tc.in_input, tc.in_blockSize)

			assert.Equal(t, tc.out_expect, hex.EncodeToString(resPadd))
		})
	}
}

func Test_PKCS7PaddUnpadd(t *testing.T) {
	tcases := []padding_tcaseSt{
		{
			caseName:      "paddUnpadd-01",
			in_input:      []byte("YELLOW SUBMARINE"),
			in_blockSize:  16,
			out_haveError: false,
			out_expect:    "YELLOW SUBMARINE",
		},
		{
			caseName:      "paddUnpadd-02",
			in_input:      []byte("YELLOW SUBMARINE"),
			in_blockSize:  15,
			out_haveError: false,
			out_expect:    "YELLOW SUBMARINE",
		},
	}

	t.Helper()

	for _, tc := range tcases {

		t.Run(tc.caseName, func(t *testing.T) {
			resPadd := PKCS7Padding(tc.in_input, tc.in_blockSize)

			resUnpadd, err := PKCS7UnPadding(resPadd)

			if tc.out_haveError {
				assert.NotEqual(t, nil, err)
			} else {
				assert.Equal(t, nil, err)
				assert.Equal(t, tc.out_expect, string(resUnpadd))
			}
		})
	}
}

type encrypt_tcaseSt struct {
	caseName string

	in_input     string
	in_secretKey string

	out_haveError bool
	out_expect    string
}

func Test_AesCbcEncrypt_HexStr(t *testing.T) {

	tcases := []encrypt_tcaseSt{
		{
			caseName:      "hex-01",
			in_input:      "Hello World",
			in_secretKey:  "ABCDEFGHIJKLMNOP",
			out_haveError: false,
			out_expect:    "20c7cbfe27e4baf919c06fefd9b9fa07",
		},
		{
			caseName:      "hex-02",
			in_input:      "Hello World",
			in_secretKey:  "1234567890abcdefghij1234567890ab",
			out_haveError: false,
			out_expect:    "d64c63f1ac3d95b1fc8dd70f0363a2b3",
		},
	}

	for _, tc := range tcases {

		t.Helper()

		t.Run(tc.caseName, func(t *testing.T) {
			cipherText_Hex, err := AesCbcEncrypt_HexStr(tc.in_input, tc.in_secretKey)
			if tc.out_haveError {
				assert.NotEqual(t, nil, err)
			} else {
				assert.Equal(t, nil, err)
				assert.Equal(t, tc.out_expect, cipherText_Hex)
			}
		})
	}
}

func Test_AesCbcEncrypt_Base64Str(t *testing.T) {

	tcases := []encrypt_tcaseSt{
		{
			caseName:      "b64-01",
			in_input:      "Hello World",
			in_secretKey:  "ABCDEFGHIJKLMNOP",
			out_haveError: false,
			out_expect:    "IMfL/ifkuvkZwG/v2bn6Bw==",
		},
		{
			caseName:      "b64-02",
			in_input:      "Hello World",
			in_secretKey:  "1234567890abcdefghij1234567890ab",
			out_haveError: false,
			out_expect:    "1kxj8aw9lbH8jdcPA2Oisw==",
		},
	}

	for _, tc := range tcases {
		t.Run(tc.caseName, func(t *testing.T) {

			cipherText_b64, err := AesCbcEncrypt_Base64Str(tc.in_input, tc.in_secretKey)
			if tc.out_haveError {
				assert.NotEqual(t, nil, err)
			} else {
				assert.Equal(t, nil, err)
				assert.Equal(t, tc.out_expect, cipherText_b64)
			}
		})
	}
}

const (
	cbcExplain = "CBC：Cipher Block Chaining，密码块链，明文被分成固定大小的块，并按顺序进行加密，每一个块（分组）要先和前一个分组加密后的数据进行 XOR 异或操作，然后再进行加密。 " +
		"这样每个密文块依赖该块之前的所有明文块，为了保持每条消息都具有唯一性，第一个数据块进行加密之前需要用初始化向量 IV 进行异或操作。 " +
		"CBC 模式是一种最常用的加密模式，它主要缺点是加密是连续的，不能并行处理，并且与 ECB 一样消息块必须填充到块大小的整倍数。"
)

func Test_AesCbcEncrypt_HexStr_Whole(t *testing.T) {

	tcases := []encrypt_tcaseSt{
		{
			caseName:      "b64-01",
			in_input:      cbcExplain,
			in_secretKey:  "ABCDEFGHIJKLMNOP",
			out_haveError: false,
			out_expect:    cbcExplain,
		},
		{
			caseName:      "b64-02",
			in_input:      cbcExplain,
			in_secretKey:  "1234567890abcdefghij1234567890ab",
			out_haveError: false,
			out_expect:    cbcExplain,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.caseName, func(t *testing.T) {

			cipherText_b64, err := AesCbcEncrypt_HexStr(tc.in_input, tc.in_secretKey)
			if tc.out_haveError {
				assert.NotEqual(t, nil, err)
			} else {

				pText, err := AesCbcDecrypt_HexStr(cipherText_b64, tc.in_secretKey)
				assert.Equal(t, nil, err)

				assert.Equal(t, tc.out_expect, pText)
			}
		})
	}
}

func Test_AesCbcEncrypt_Base64Str_Whole(t *testing.T) {

	tcases := []encrypt_tcaseSt{
		{
			caseName:      "b64-01",
			in_input:      cbcExplain,
			in_secretKey:  "ABCDEFGHIJKLMNOP",
			out_haveError: false,
			out_expect:    cbcExplain,
		},
		{
			caseName:      "b64-02",
			in_input:      cbcExplain,
			in_secretKey:  "1234567890abcdefghij1234567890ab",
			out_haveError: false,
			out_expect:    cbcExplain,
		},
	}

	for _, tc := range tcases {
		t.Run(tc.caseName, func(t *testing.T) {

			cipherText_b64, err := AesCbcEncrypt_Base64Str(tc.in_input, tc.in_secretKey)
			if tc.out_haveError {
				assert.NotEqual(t, nil, err)
			} else {

				pText, err := AesCbcDecrypt_Base64Str(cipherText_b64, tc.in_secretKey)
				assert.Equal(t, nil, err)

				assert.Equal(t, tc.out_expect, pText)
			}
		})
	}
}
