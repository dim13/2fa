package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type key struct {
	name    string
	otp     func() int64
	otpName string
	alg     func() hash.Hash
	algName string
	digits  int
	issuer  string
	counter int64
	period  int64
	secret  []byte
}

func (k *key) totp() int64 {
	return time.Now().Unix() / k.period
}

func (k *key) hotp() int64 {
	k.counter++ // pre-increment rfc4226 section 7.2.
	return k.counter
}

func (k *key) left() time.Duration {
	return time.Second * time.Duration(k.period-int64(time.Now().Second())%k.period)
}

var pow10tab = [...]int{
	1e00, 1e01, 1e02, 1e03, 1e04, 1e05, 1e06, 1e07, 1e08, 1e09,
	1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18,
}

func (k *key) eval() int {
	h := hmac.New(k.alg, k.secret)
	binary.Write(h, binary.BigEndian, k.otp())
	hashed := h.Sum(nil)
	offset := hashed[h.Size()-1] & 15
	result := binary.BigEndian.Uint32(hashed[offset:]) & (1<<31 - 1)
	return int(result) % pow10tab[k.digits]
}

func (k *key) UnmarshalText(text []byte) error {
	u, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	q := u.Query()
	switch o := strings.ToLower(u.Host); o {
	case "totp":
		k.otp = k.totp
		k.otpName = o
	case "hotp":
		k.otp = k.hotp
		k.otpName = o
	default:
		k.otp = k.totp
		k.otpName = "totp"
	}
	k.name = strings.TrimPrefix(u.Path, "/")
	switch a := strings.ToUpper(q.Get("algorithm")); a {
	case "SHA1":
		k.alg = sha1.New
		k.algName = a
	case "SHA256":
		k.alg = sha256.New
		k.algName = a
	case "SHA512":
		k.alg = sha512.New
		k.algName = a
	case "MD5":
		k.alg = md5.New
		k.algName = a
	default:
		k.alg = sha1.New
	}
	k.digits = 6
	if v := q.Get("digits"); v != "" {
		digits, err := strconv.ParseInt(v, 10, 0)
		if err != nil {
			return err
		}
		k.digits = int(digits)
	}
	k.issuer = q.Get("issuer")
	if v := q.Get("counter"); v != "" {
		counter, err := strconv.ParseInt(v, 10, 0)
		if err != nil {
			return err
		}
		k.counter = counter
	}
	k.period = 30
	if v := q.Get("period"); v != "" {
		period, err := strconv.ParseInt(v, 10, 0)
		if err != nil {
			return err
		}
		k.period = period
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q.Get("secret"))
	if err != nil {
		return fmt.Errorf("%s: %w", q.Get("secret"), err)
	}
	k.secret = secret
	return nil
}

func (k *key) URL() *url.URL {
	v := make(url.Values)
	// required
	v.Add("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k.secret))
	// strongly recommended
	if k.issuer != "" {
		v.Add("issuer", k.issuer)
	}
	// optional
	if k.algName != "" {
		v.Add("algorithm", k.algName)
	}
	// optional
	if k.digits > 0 {
		v.Add("digits", fmt.Sprint(k.digits))
	}
	// required if type is hotp
	if k.otpName == "hotp" {
		v.Add("counter", fmt.Sprint(k.counter))
	}
	// optional if type is totp
	if k.otpName == "totp" && k.period > 0 {
		v.Add("period", fmt.Sprint(k.period))
	}
	return &url.URL{
		Scheme:   "otpauth",
		Host:     k.otpName,
		Path:     k.name,
		RawQuery: v.Encode(),
	}
}
