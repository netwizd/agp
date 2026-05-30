package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed static/*
var staticFS embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || !hasKnownAssetExtension(name) {
			r = cloneRequestWithPath(r, "/")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func hasKnownAssetExtension(name string) bool {
	switch path.Ext(name) {
	case ".css", ".js", ".ico", ".png", ".jpg", ".jpeg", ".webp", ".svg":
		return true
	default:
		return false
	}
}

func cloneRequestWithPath(r *http.Request, requestPath string) *http.Request {
	clone := r.Clone(r.Context())
	clone.URL.Path = requestPath
	return clone
}
