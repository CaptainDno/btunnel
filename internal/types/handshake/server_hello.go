package handshake

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/CaptainDno/btunnel/internal/types/message"
	"io"
	"regexp"
	"strconv"
)

type ServerHello struct {
	AcceptedClientID   string
	ServerVersion      string
	AcceptedSessionKey []byte
	FirstPiece         uint32
	LastPiece          uint32
	BodyLength         int
	Nonce              []byte
}

func FromClientHello(clientHello *ClientHello, serverVersion string, firstPiece, lastPiece uint32) (*ServerHello, error) {

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil || bytes.Equal(nonce, clientHello.Nonce) {
		return nil, err
	}

	return &ServerHello{
		AcceptedClientID:   clientHello.ClientID,
		ServerVersion:      serverVersion,
		AcceptedSessionKey: clientHello.ProposedSessionKey,
		FirstPiece:         firstPiece,
		LastPiece:          lastPiece,
		BodyLength:         clientHello.BodyLength,
		Nonce:              nonce,
	}, nil
}

func (hello *ServerHello) WriteServerHello(writer io.Writer, aead cipher.AEAD) error {
	serverHelloBody := make([]byte, hello.BodyLength)
	header := fmt.Sprintf("###\nSESSION START ACCEPTED\nSERVER VER: %s\nCLIENT ID: %s\nFIRST PIECE: %d\nLAST PIECE: %d\n###", hello.ServerVersion, hello.AcceptedClientID, hello.FirstPiece, hello.LastPiece)

	pos := copy(serverHelloBody, header)
	pos += copy(serverHelloBody[pos:], hello.AcceptedSessionKey)

	_, err := rand.Read(serverHelloBody[pos:])
	if err != nil {
		return err
	}

	// Send our client hello to server
	msg := message.BittorrentMessage{
		ID:      message.MsgBitfield,
		Payload: append(hello.Nonce, aead.Seal(nil, hello.Nonce, serverHelloBody, nil)...),
	}
	return msg.Write(writer)
}

var serverRegex = regexp.MustCompile(`(?m)###\nSESSION START ACCEPTED\nSERVER VER: (\S*)\nCLIENT ID: (\S*)\nFIRST PIECE: (\S*)\nLAST PIECE: (\S*)\n###`)

func ReadServerHello(reader io.Reader, aead cipher.AEAD) (*ServerHello, error) {
	msg, err := message.Read(reader)
	if err != nil {
		return nil, err
	}

	if len(msg.Payload) < 1024+12 {
		return nil, errors.New("body too small for expected protocol")
	}

	nonce := msg.Payload[:12]

	// Decrypt body
	body, err := aead.Open(nil, nonce, msg.Payload[12:], nil)
	if err != nil {
		return nil, err
	}
	//log.Println(string(body))

	if !bytes.Equal(body[:3], []byte{'#', '#', '#'}) {
		return nil, errors.New("server hello header malformed")
	}

	matches := serverRegex.FindSubmatch(body)
	if matches == nil || len(matches) != 5 {
		return nil, errors.New("server hello header malformed")
	}

	firstPiece, err := strconv.ParseUint(string(matches[3]), 10, 32)
	if err != nil {
		return nil, err
	}

	lastPiece, err := strconv.ParseUint(string(matches[4]), 10, 32)
	if err != nil {
		return nil, err
	}

	return &ServerHello{
		AcceptedClientID:   string(matches[2]),
		ServerVersion:      string(matches[1]),
		AcceptedSessionKey: body[len(matches[0]) : len(matches[0])+32],
		FirstPiece:         uint32(firstPiece),
		LastPiece:          uint32(lastPiece),
		BodyLength:         len(body),
		Nonce:              nonce,
	}, nil
}
