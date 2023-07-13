package dysign

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "net/url"
    "strings"
    "time"
)

const (
    timeForamt = "2006-01-02T15:04:05Z07"
)

const (
    SignatureMethod_HMAC_SHA1 = "HMAC-SHA1"
)

/*
GetTimestamp get timestamp

use ISO8601 standard, UTC time and timezone flag,
format is yyyy-MM-ddTHH:mm:ssZ

@return the timestamp
*/
func GetTimestamp() (timeStr string) {

    var (
        tZone = time.FixedZone("UTC", 0)
        now   = time.Now()
    )

    timeStr = now.In(tZone).Format(timeForamt)

    return timeStr
}

/*
TimestampToUnixSec convert timestamp to seconds in unix format

@return tusec int64 : seconds in unix format
@return err error : error
*/
func TimestampToUnixSec(timestamp string) (tusec int64, err error) {

    var (
        t time.Time
    )

    t, err = time.Parse(timeForamt, timestamp)
    if nil != err {
        return
    }

    tusec = t.Unix()

    return
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
