package sshmuxer

import (
	"fmt"
	"log"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// handleRequests handles incoming requests from an SSH connection.
func handleRequests(reqs <-chan *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	for req := range reqs {
		if viper.GetBool("debug") {
			log.Println("Main Request Info", req.Type, req.WantReply, string(req.Payload))
		}
		handleRequest(req, sshConn, state)
	}
}

// handleRequest handles a incoming request from a SSH connection.
func handleRequest(newRequest *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	switch req := newRequest.Type; req {
	case "tcpip-forward":
		go checkSession(newRequest, sshConn, state)
		handleRemoteForward(newRequest, sshConn, state)
	case "keepalive@openssh.com":
		err := newRequest.Reply(true, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
	default:
		err := newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
	}
}

// checkSession will check a session to see that it has a session.
func checkSession(newRequest *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	sshConn.SetupLock.Lock()
	if sshConn.CleanupHandler {
		sshConn.SetupLock.Unlock()
		return
	}
	sshConn.CleanupHandler = true
	sshConn.SetupLock.Unlock()
	select {
	case <-sshConn.Session:
		return
	case <-time.After(2 * time.Second):
		go func() {
			for {
				select {
				case <-sshConn.Messages:
					break
				case <-sshConn.Close:
					return
				}
			}
		}()

		err := sshConn.SSHConn.Wait()
		if err != nil {
			log.Println("Waited for ssh conn without session:", err)
		}
		sshConn.CleanUp(state)
		return
	}
}

// handleChannels handles a SSH connection's channel requests.
func handleChannels(chans <-chan ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	for newChannel := range chans {
		if viper.GetBool("debug") {
			log.Println("Main Channel Info", newChannel.ChannelType(), string(newChannel.ExtraData()))
		}
		go handleChannel(newChannel, sshConn, state)
	}
}

//  handleChannel handles a SSH connection's channel request.
func handleChannel(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		close(sshConn.Session)
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
