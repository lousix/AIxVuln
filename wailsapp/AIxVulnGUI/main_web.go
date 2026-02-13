package main

import (
	"AIxVuln/Web"
	"io/fs"
)

func runWebMode(port string, assets fs.FS) {
	server := Web.NewServer()
	server.StartWebServerWithUIFS(port, assets)
}
