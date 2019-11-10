package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func handleRequests(reqs <-chan *ssh.Request, sshConn *SSHConnection, state *State) {
	for req := range reqs {
		if *debug {
			log.Println("Main Request Info", req.Type, req.WantReply, string(req.Payload))
		}
		go handleRequest(req, sshConn, state)
	}
}

func handleRequest(newRequest *ssh.Request, sshConn *SSHConnection, state *State) {
	switch req := newRequest.Type; req {
	case "tcpip-forward":
		handleRemoteForward(newRequest, sshConn, state)
	default:
		err := newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *SSHConnection, state *State) {
	for newChannel := range chans {
		if *debug {
			log.Println("Main Channel Info", newChannel.ChannelType(), string(newChannel.ExtraData()))
		}
		go handleChannel(newChannel, sshConn, state)
	}
}

func handleChannel(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		handleSession(newChannel, sshConn, state)
	case "direct-tcpip":
		handleAlias(newChannel, sshConn, state)
	default:
		err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
		if err != nil {
			log.Println("Error rejecting socket channel:", err)
		}
	}
}
