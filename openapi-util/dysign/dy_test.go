package dysign

import (
    "net/url"
    "testing"
    "time"

    "github.com/bmizerany/assert"
)

func Test_GetTimestamp(t *testing.T) {

    const timeForamt = "2006-01-02T15:04:05Z07"

    var (
        tZone = time.FixedZone("UTC", 0)
        now   = time.Unix(1689214073, 0)
    )

    timeStr := now.In(tZone).Format(timeForamt)

    assert.Equal(t, "2023-07-13T02:07:53Z", timeStr)
}

func Test_TimestampToUnixSec(t *testing.T) {

    tunix, err := TimestampToUnixSec("2023-07-13T02:07:53Z")
    assert.Equal(t, nil, err)
    assert.Equal(t, int64(1689214073), tunix)

    tunix, err = TimestampToUnixSec("2023-07-13T17:15:31+08")
    assert.Equal(t, nil, err)
    assert.Equal(t, int64(1689239731), tunix)
}

func Test_urlencode(t *testing.T) {

    urlEncoder := url.Values{}

    urlEncoder.Add("Timestamp", "2023-07-12T15:34:35Z")
    urlEncoder.Add("SignatureNonce", "15215528852396")

    urlEncoded := urlEncoder.Encode()

    assert.Equal(t, "SignatureNonce=15215528852396&Timestamp=2023-07-12T15%3A34%3A35Z", urlEncoded)
}

func Test_GetHmacsha1Signature(t *testing.T) {

    params := map[string]string{
        "Method":           "smsRouteCreditControl",
        "AccessKeyId":      "acek-001",
        "Timestamp":        "2023-01-01T14:21:46Z",
        "Version":          "2023-07-11",
        "SignatureNonce":   "edb2b34af0af9a6d14deaf7c1a5315eb",
        "SignatureMethod":  "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "CustomerId":       "10010",
        "FreezeStatus":     "ACTIVE",
    }

    _, signature := GetHmacsha1Signature(params, "duh04756302dGYUEH937GFFUJE63468")
    expectedSignature := "TgEiEEyOK6T/G4dQVOkmD0w7cTs="

    assert.Equal(t, expectedSignature, signature)
}
