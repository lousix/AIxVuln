package main

import (
	"AIxVuln/Web"
	"context"
	"fmt"
	"net"
	"strconv"
)

// App struct
type App struct {
	ctx context.Context
	apiBaseURL string
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	port := preferPortOrFree(9999)
	a.apiBaseURL = "http://127.0.0.1:" + strconv.Itoa(port)
	go func() {
		server := Web.NewServer()
		server.StartWebServer(strconv.Itoa(port))
	}()
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) GetAPIBaseURL() string {
	return a.apiBaseURL
}

// GetBasicAuthUser and GetBasicAuthPassword return empty strings.
// Users are now managed in SQLite; the frontend uses the init wizard + token login flow.
func (a *App) GetBasicAuthUser() string {
	return ""
}

func (a *App) GetBasicAuthPassword() string {
	return ""
}

func preferPortOrFree(prefer int) int {
	if canListen(prefer) {
		return prefer
	}
	return findFreePort()
}

func canListen(port int) bool {
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func findFreePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 9999
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port
}
