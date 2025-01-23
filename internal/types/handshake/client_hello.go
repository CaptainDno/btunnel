package handshake

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/CaptainDno/btunnel/internal/types/message"
	"github.com/CaptainDno/btunnel/internal/utils"
	"io"
	"regexp"
	"strconv"
)

type ClientHello struct {
	ClientID           string
	ClientVersion      string
	ProposedSessionKey []byte
	BlockSize          uint32
	PieceSize          uint32
	FirstPiece         uint32
	LastPiece          uint32
	BodyLength         int
	Nonce              []byte
}

var clientRegex = regexp.MustCompile(`(?m)###\nSESSION START\nCLIENT VER: (\S*)\nCLIENT ID: (\S*)\nBLOCK SIZE: (\S*)\nPIECE SIZE: (\S*)\nFIRST PIECE: (\S*)\nLAST PIECE: (\S*)\n###`)

func NewClientHello(clientId, clientVersion string, sessionKey []byte) (*ClientHello, error) {
	bodySize, err := utils.GenerateRandomInt(1024, 4096)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return &ClientHello{
		ClientID:           clientId,
		ClientVersion:      clientVersion,
		ProposedSessionKey: sessionKey,
		BodyLength:         bodySize,
		Nonce:              nonce,
	}, nil
}

// WriteClientHello writes client hello to specified writer
func (hello *ClientHello) WriteClientHello(writer io.Writer, aead cipher.AEAD, blockSize, pieceSize, startPiece, endPiece uint32) error {
	clientHelloBody := make([]byte, hello.BodyLength)

	header := fmt.Sprintf("###\nSESSION START\n"+
		"CLIENT VER: %s\n"+
		"CLIENT ID: %s\n"+
		"BLOCK SIZE: %d\n"+
		"PIECE SIZE: %d\n"+
		"FIRST PIECE: %d\n"+
		"LAST PIECE: %d\n"+
		"###", hello.ClientVersion, hello.ClientID, blockSize, pieceSize, startPiece, endPiece)

	pos := copy(clientHelloBody, header)
	pos += copy(clientHelloBody[pos:], hello.ProposedSessionKey)

	// The rest should be random
	_, err := rand.Read(clientHelloBody[pos:])
	if err != nil {
		return err
	}

	// Send our client hello to server
	msg := message.BittorrentMessage{
		ID:      message.MsgBitfield,
		Payload: append(hello.Nonce, aead.Seal(nil, hello.Nonce, clientHelloBody, nil)...),
	}
	return msg.Write(writer)
}

// ReadClientHello parses client hello from reader
func ReadClientHello(reader io.Reader, aead cipher.AEAD) (*ClientHello, error) {
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
	if !bytes.Equal(body[:3], []byte{'#', '#', '#'}) {
		return nil, errors.New("client hello header malformed")
	}

	matches := clientRegex.FindSubmatch(body)
	if matches == nil || len(matches) != 7 {
		return nil, errors.New("client hello header malformed")
	}

	blockSize, err := strconv.ParseUint(string(matches[3]), 10, 32)
	if err != nil {
		return nil, err
	}

	pieceSize, err := strconv.ParseUint(string(matches[4]), 10, 32)
	if err != nil {
		return nil, err
	}

	firstPiece, err := strconv.ParseUint(string(matches[5]), 10, 32)
	if err != nil {
		return nil, err
	}

	lastPiece, err := strconv.ParseUint(string(matches[6]), 10, 32)
	if err != nil {
		return nil, err
	}

	return &ClientHello{
		ClientID:           string(matches[2]),
		ClientVersion:      string(matches[1]),
		ProposedSessionKey: body[len(matches[0]) : len(matches[0])+32],
		BlockSize:          uint32(blockSize),
		PieceSize:          uint32(pieceSize),
		FirstPiece:         uint32(firstPiece),
		LastPiece:          uint32(lastPiece),
		BodyLength:         len(body),
		Nonce:              nonce,
	}, nil
}
