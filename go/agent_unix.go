//go:build !windows

package main

import (
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigners returns the SSH agent's identities, closing the connection
// when done.
func agentSigners() ([]ssh.Signer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("SSH_AUTH_SOCK not set")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return agent.NewClient(c).Signers()
}
