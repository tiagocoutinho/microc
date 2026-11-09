package main

import (
	"os"
	"os/exec"
)

func main() {
	print("Hello\n")
	cmd := exec.Command("ls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}
