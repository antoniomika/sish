package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func handleRequests(reqs <-chan *ssh.Request, sshConn *SSHConnection, state *State) {
	for req := range reqs {
		log.Println("Main Request Info", req.Type, req.WantReply, string(req.Payload))
		go handleRequest(req, sshConn, state)
	}
}

func handleRequest(newRequest *ssh.Request, sshConn *SSHConnection, state *State) {
	switch req := newRequest.Type; req {
	case "tcpip-forward":
		handleRemoteForward(newRequest, sshConn, state)
	default:
		newRequest.Reply(false, nil)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *SSHConnection, state *State) {
	for newChannel := range chans {
		log.Println("Main Channel Info", newChannel.ChannelType(), string(newChannel.ExtraData()))
		go handleChannel(newChannel, sshConn, state)
	}
}

func handleChannel(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		handleSession(newChannel, sshConn, state)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
	}
}
