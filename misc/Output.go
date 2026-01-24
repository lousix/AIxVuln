package misc

import (
	"fmt"
	"log"
	"time"
)

func Info(mod string, msg string, eventHandler func(string, string, int)) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	m := fmt.Sprintf("[%s][*][%s]: %s", timestamp, mod, msg)
	if eventHandler != nil {
		eventHandler(mod, msg, 1)
	}
	fmt.Println(m)
}

func Success(mod string, msg string, eventHandler func(string, string, int)) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	m := fmt.Sprintf("[%s][+][%s]: %s", timestamp, mod, msg)
	if eventHandler != nil {
		eventHandler(mod, msg, 1)
	}
	fmt.Println(m)
}

func Warn(mod string, msg string, eventHandler func(string, string, int)) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	m := fmt.Sprintf("[%s][!][%s]: %s", timestamp, mod, msg)
	if eventHandler != nil {
		eventHandler(mod, msg, 2)
	}
	fmt.Println(m)
}

func Error(mod string, msg string, eventHandler func(string, string, int)) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	m := fmt.Sprintf("[%s][-][%s]: %s", timestamp, mod, msg)
	if eventHandler != nil {
		eventHandler(mod, msg, 3)
		return
	}
	log.Fatal(m)
}
