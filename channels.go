package main

import (
	"io"
	"log"

	"golang.org/x/crypto/ssh"
)

func handleSession(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	if *debug {
		log.Println("Handling session for connection:", connection)
	}

	go func() {
		for {
			select {
			case c := <-sshConn.Messages:
				connection.Write([]byte(c))
				connection.Write([]byte{'\r', '\n'})
			case <-sshConn.Close:
				return
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
					sshConn.CleanUp(state)
				}
				break
			}

			if dataRead != 0 {
				if data[0] == 3 {
					sshConn.CleanUp(state)
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
				if *debug {
					log.Println("Sub Channel Type", req.Type, req.WantReply, string(req.Payload))
				}
			}
		}
	}()
}
