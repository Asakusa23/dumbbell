package main

import (
	"crypto/tls"
	"os/exec"
)

func run(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

var tlsConfig = &tls.Config{InsecureSkipVerify: true}
