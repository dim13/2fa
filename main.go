package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
		if strings.HasPrefix(s.Text(), "otpauth:") {
			var k key
			if err := k.UnmarshalText(s.Bytes()); err != nil {
				return nil, err
			}
			keys = append(keys, k)
		}
	}
	return keys, s.Err()
}

func homeDir(s string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, s)
}

func main() {
	chainFile := flag.String("file", homeDir(".2fa"), "keychain file")
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
	for _, k := range keys {
		if len(os.Args) > 1 && !k.match(os.Args[1]) {
			continue
		}
		k.WriteTo(w)
	}
}
