package main

import (
	"AIxVuln/Web"
	"AIxVuln/misc"
	"embed"
	"io/fs"
	"log"
)

//go:embed all:dockerfile
var dockerfileFS embed.FS

func init() {
	sub, err := fs.Sub(dockerfileFS, "dockerfile")
	if err != nil {
		log.Fatal("embed dockerfile: ", err)
	}
	misc.SetDockerfileFS(sub)
	err = misc.CreateDirIfNotExists("data/temp/")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	defer misc.CleanupDockerfiles()
	server := Web.NewServer()
	server.StartWebServer("9999")
}
