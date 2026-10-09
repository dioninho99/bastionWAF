package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var files embed.FS

func Handler() http.Handler {
	root, _ := fs.Sub(files, "static")
	return http.FileServer(http.FS(root))
}
