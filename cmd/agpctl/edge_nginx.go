package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/netwizd/agp/internal/reverseproxy/nginx"
)

// edgeNginx generates reviewable config only. It never writes/reloads Nginx.
func edgeNginx(args []string) error {
	f := flag.NewFlagSet("nginx-edge", flag.ContinueOnError)
	origin := f.String("origin", "", "canonical HTTPS application origin")
	socket := f.String("socket", "", "private EdgeAuth Unix socket")
	cert := f.String("certificate", "", "explicit TLS certificate path")
	key := f.String("key", "", "explicit TLS private key path")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *origin == "" || *socket == "" || *cert == "" || *key == "" {
		return errors.New("nginx-edge requires --origin, --socket, --certificate and --key")
	}
	config, e := nginx.GenerateEdgeGatewayServerWithTLS(*origin, *socket, *cert, *key)
	if e != nil {
		return e
	}
	fmt.Print(config)
	return nil
}
