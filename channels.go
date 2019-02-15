package main

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

func handleSession(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	fmt.Println("Handling session for connection:", connection)

	cleanUp := func() {
		close(sshConn.Close)
		close(sshConn.Messages)
		sshConn.SSHConn.Close()
		state.SSHConnections.Delete(sshConn.SSHConn.RemoteAddr())
	}

	go func() {
		for {
			select {
			case c := <-sshConn.Messages:
				connection.Write([]byte(c))
				connection.Write([]byte{'\r', '\n'})
			case <-sshConn.Close:
				return
			default:
				break
			}
		}
	}()

	sshConn.Messages <- "Press Ctrl-C to close the session."

	go func() {
		for {
			data := make([]byte, 4096)
			dataRead, err := connection.Read(data)
			if err != nil && err == io.EOF {
				select {
				case <-sshConn.Close:
					break
				default:
					cleanUp()
				}
				break
			}

			if dataRead != 0 {
				if data[0] == 3 {
					cleanUp()
				}
			}
		}
	}()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				req.Reply(true, nil)
			default:
				fmt.Println("Sub Channel Type", req.Type, req.WantReply, string(req.Payload))
			}
		}
	}()
}
