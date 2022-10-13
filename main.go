package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type key struct {
	name    string
	otp     func() uint64
	alg     func() hash.Hash
	digits  int
	issuer  string
	counter uint64
	period  uint64
	secret  []byte
}

func (k *key) totp() uint64 {
	return uint64(time.Now().Unix()) / k.period
}

func (k *key) hotp() uint64 {
	k.counter++ // pre-increment rfc4226 section 7.2.
	return k.counter
}

func (k *key) eval() int {
	h := hmac.New(k.alg, k.secret)
	binary.Write(h, binary.BigEndian, k.otp())
	hashed := h.Sum(nil)
	offset := hashed[h.Size()-1] & 15
	result := binary.BigEndian.Uint32(hashed[offset:]) & (1<<31 - 1)
	return int(result) % int(math.Pow10(k.digits))
}

func (k *key) UnmarshalText(text []byte) error {
	u, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	q := u.Query()
	switch strings.ToLower(u.Host) {
	case "totp":
		k.otp = k.totp
	case "hotp":
		k.otp = k.hotp
	default:
		k.otp = k.totp
	}
	k.name = strings.TrimPrefix(u.Path, "/")
	switch strings.ToUpper(q.Get("algorithm")) {
	case "SHA1":
		k.alg = sha1.New
	case "SHA256":
		k.alg = sha256.New
	case "SHA512":
		k.alg = sha512.New
	case "MD5":
		k.alg = md5.New
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
		k.counter = uint64(counter)
	}
	k.period = 30
	if v := q.Get("period"); v != "" {
		period, err := strconv.ParseInt(v, 10, 0)
		if err != nil {
			return err
		}
		k.period = uint64(period)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q.Get("secret"))
	if err != nil {
		return fmt.Errorf("%s: %w", q.Get("secret"), err)
	}
	k.secret = secret
	return nil
}

func keychain() ([]key, error) {
	fd, err := os.Open(os.ExpandEnv("$HOME/.2fax"))
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	s := bufio.NewScanner(fd)
	var keys []key
	for s.Scan() {
		var k key
		if err := k.UnmarshalText(s.Bytes()); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, s.Err()
}

func main() {
	keys, err := keychain()
	if err != nil {
		log.Fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	for _, v := range keys {
		if len(os.Args) > 1 {
			s := strings.ToLower(os.Args[1])
			if !strings.Contains(strings.ToLower(v.issuer), s) && !strings.Contains(strings.ToLower(v.name), s) {
				continue
			}
		}
		fmt.Fprintf(w, "%0*d\t%s\t%s\n", v.digits, v.eval(), v.issuer, v.name)
	}
}
