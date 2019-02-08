package main

import (
	"bytes"
	"io"
	"os/exec"
	"runtime"
)

var outb bytes.Buffer

type Shell struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func (s *Shell) Init() {
	if runtime.GOOS == "windows" {
		s.cmd = exec.Command("powershell")
	}

	s.stdin, _ = s.cmd.StdinPipe()
	s.cmd.Stdout = &outb
	s.cmd.Stderr = &outb
	go s.cmd.Run()

}

func (s *Shell) Input(order string) {
	s.stdin.Write([]byte(order))
}

func (s *Shell) ReadOutput() []byte {
	line, _ := outb.ReadBytes('\n')
	return line
}
