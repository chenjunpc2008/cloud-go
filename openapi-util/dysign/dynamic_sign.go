package dysign

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "net/url"
    "strings"
    "time"
)

/*
GetTimestamp get timestamp

按照ISO8601标准表示，并需要使用UTC时间及时区标识，格式为yyyy-MM-ddTHH:mm:ssZ

@return the timestamp
*/
func GetTimestamp() (timeStr string) {
    const timeForamt = "2006-01-02T15:04:05Z07"

    var (
        tZone = time.FixedZone("UTC", 0)
        now   = time.Now()
    )

    timeStr = now.In(tZone).Format(timeForamt)

    return timeStr
}

/*
GetHmacsha1Signature get signature according to signedParams and secret

@param toSignParams : params which need to be signed
@param secret : AccessKeySecret
@return the signature
*/
func GetHmacsha1Signature(toSignedParams map[string]string, secret string) (signature string) {

    stringToSign := buildStringToSign(toSignedParams)
    signature = sign(stringToSign, secret, "&")

    return signature
}

func buildStringToSign(toSignedParams map[string]string) (stringToSign string) {

    stringToSign = getUrlFormedMap(toSignedParams)
    stringToSign = strings.Replace(stringToSign, "+", "%20", -1)
    stringToSign = strings.Replace(stringToSign, "*", "%2A", -1)
    stringToSign = strings.Replace(stringToSign, "%7E", "~", -1)
    stringToSign = url.QueryEscape(stringToSign)
    return
}

func getUrlFormedMap(source map[string]string) (urlEncoded string) {

    urlEncoder := url.Values{}
    for key, value := range source {
        urlEncoder.Add(key, value)
    }
    urlEncoded = urlEncoder.Encode()
    return
}

func sign(stringToSign, accessKeySecret, secretSuffix string) string {
    secret := accessKeySecret + secretSuffix
    signedBytes := shaHmac1(stringToSign, secret)
    signedString := base64.StdEncoding.EncodeToString(signedBytes)
    return signedString
}

func shaHmac1(source, secret string) []byte {
    key := []byte(secret)
    hmac := hmac.New(sha1.New, key)
    hmac.Write([]byte(source))
    return hmac.Sum(nil)
}
