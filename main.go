package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
)

func addKey(fname, s string) error {
	fd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer fd.Close()
	var k key
	if err := k.UnmarshalText([]byte(s)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(fd, k.URL()); err != nil {
		return err
	}
	return nil
}

func keychain(fname string) ([]key, error) {
	fd, err := os.OpenFile(fname, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	s := bufio.NewScanner(fd)
	var keys []key
	for s.Scan() {
		// skip comments
		if strings.HasPrefix(s.Text(), "#") {
			continue
		}
		var k key
		if err := k.UnmarshalText(s.Bytes()); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, s.Err()
}

func main() {
	chainFile := flag.String("file", os.ExpandEnv("$HOME/.2fa"), "keychain file")
	add := flag.String("add", "", "add key (example: otpauth://totp/Example:alice@google.com?issuer=Example&secret=JBSWY3DPEHPK3PXP)")
	flag.Parse()
	if *add != "" {
		if err := addKey(*chainFile, *add); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	keys, err := keychain(*chainFile)
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
		fmt.Fprintf(w, "%0*d\t%s\t%s\t%v\n", v.digits, v.eval(), v.issuer, v.name, v.left())
	}
}
