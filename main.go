package main

import (
	"AIxVuln/Web"
	"AIxVuln/misc"
	"log"
)

func init() {
	err := misc.CreateDirIfNotExists("data/.m2/")
	if err != nil {
		log.Fatal(err)
	}
	err = misc.CreateDirIfNotExists("data/.npm/")
	if err != nil {
		log.Fatal(err)
	}
	err = misc.CreateDirIfNotExists("data/temp/")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	server := Web.NewServer()
	server.StartWebServer("9999")
}
