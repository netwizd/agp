package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/netwizd/agp/internal/auth"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "hash-password" {
		fmt.Fprintln(os.Stderr, "usage: agpctl hash-password")
		os.Exit(2)
	}

	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "read password from stdin: %v\n", err)
		os.Exit(1)
	}
	password = strings.TrimRight(password, "\r\n")

	hash, err := auth.HashPassword(password, auth.DefaultArgon2idParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
