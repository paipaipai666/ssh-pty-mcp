//go:build windows

package main

import (
	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigners returns the identities of the OpenSSH agent named pipe,
// closing the connection when done.
func agentSigners() ([]ssh.Signer, error) {
	conn, err := winio.DialPipe(`\\.\pipe\openssh-ssh-agent`, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return agent.NewClient(conn).Signers()
}
