package sshmuxer

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/antoniomika/sish/utils"
	"golang.org/x/crypto/ssh"
)

// handleRequests handles incoming requests from an SSH connection.
func handleRequests(reqs <-chan *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	for req := range reqs {
		slog.Debug("main request info",
			"type", req.Type,
			"wantReply", req.WantReply,
			"payload", req.Payload,
		)

		handleRequest(req, sshConn, state)
	}
}

// handleRequest handles a incoming request from a SSH connection.
func handleRequest(newRequest *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	switch req := newRequest.Type; req {
	case "tcpip-forward":
		go checkSession(newRequest, sshConn, state)
		handleRemoteForward(newRequest, sshConn, state)
	case "cancel-tcpip-forward":
		handleCancelRemoteForward(newRequest, sshConn, state)
	case "keepalive@openssh.com":
		err := newRequest.Reply(true, nil)
		if err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
	default:
		err := newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
	}
}

// checkSession will check a session to see that it has a session.
func checkSession(_ *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
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
				case <-sshConn.Close:
					return
				}
			}
		}()

		err := sshConn.SSHConn.Wait()
		sshConn.Logger().Debug(
			"connection without session closed",
			"err", err,
		)
		sshConn.CleanUp(state)
		return
	}
}

// handleChannels handles a SSH connection's channel requests.
func handleChannels(chans <-chan ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	for newChannel := range chans {
		slog.Debug("main channel info",
			"channelType", newChannel.ChannelType(),
			"extraData", newChannel.ExtraData(),
		)
		go handleChannel(newChannel, sshConn, state)
	}
}

// handleChannel handles a SSH connection's channel request.
func handleChannel(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		if !sshConn.OpenSession() {
			err := newChannel.Reject(ssh.Prohibited, "only one session is allowed per connection")
			if err != nil {
				slog.Error(
					"error rejecting session channel",
					"err", err,
				)
			}
			return
		}

		handleSession(newChannel, sshConn, state)
	case "direct-tcpip":
		handleAlias(newChannel, sshConn, state)
	default:
		err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
		if err != nil {
			slog.Error(
				"error rejecting socket channel",
				"err", err,
			)
		}
	}
}
