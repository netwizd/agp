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
		entry := ""
		for _, candidate := range []string{"auth", "config", "directory"} {
			if name == candidate+"-ui" || strings.HasPrefix(name, candidate+"-ui/") {
				entry = candidate
				break
			}
		}
		if entry != "" {
			asset := strings.TrimPrefix(strings.TrimPrefix(name, entry+"-ui"), "/")
			if asset == "" || path.Ext(asset) == "" {
				asset = "index.html"
			}
			// Missing bundles fail closed: never return the legacy HTML as JavaScript.
			info, err := fs.Stat(sub, entry+"/"+asset)
			if err != nil || info.IsDir() {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			if asset == "index.html" {
				// FileServer redirects /index.html; ServeContent keeps application deep links intact.
				data, err := fs.ReadFile(sub, entry+"/index.html")
				if err != nil {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				http.ServeContent(w, r, "index.html", info.ModTime(), strings.NewReader(string(data)))
				return
			}
			fileServer.ServeHTTP(w, cloneRequestWithPath(r, "/"+entry+"/"+asset))
			return
		}
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
