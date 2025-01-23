package message

import (
	"encoding/binary"
	"errors"
	"io"
)

// / DOCS:
// / Unless specified otherwise, all integers in the peer wire protocol are encoded as four byte big-endian values. This includes the length prefix on all messages that come after the handshake.
type msgID byte

const (
	MsgChoke msgID = 0

	MsgUnchoke msgID = 1

	MsgInterested msgID = 2

	MsgNotInterested msgID = 3

	MsgHave msgID = 4

	MsgBitfield msgID = 5

	MsgRequest msgID = 6

	MsgPiece msgID = 7
)

type BittorrentMessage struct {
	ID      msgID
	Payload []byte
}

func (m *BittorrentMessage) Write(writer io.Writer) error {
	length := uint32(len(m.Payload) + 1)
	buf := make([]byte, length+4)

	binary.BigEndian.PutUint32(buf, length)
	buf[4] = byte(m.ID)
	copy(buf[5:], m.Payload)

	_, err := writer.Write(buf)
	return err
}

var EmptyPayload []byte

func Read(r io.Reader) (*BittorrentMessage, error) {
	buf := make([]byte, 5)

	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(buf)

	if length == 0 {
		return nil, errors.New("messages with zero length are not supported")
	}

	if length == 1 {
		msg := &BittorrentMessage{
			ID:      msgID(buf[4]),
			Payload: EmptyPayload,
		}
		return msg, msg.Validate()
	}

	id := msgID(buf[4])
	//log.Printf("msg id: %d", id)
	// We read only header!!!
	if id == MsgPiece {
		length = 9
	}

	buf = make([]byte, length-1)
	//log.Printf("reading payload %d", length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	//log.Printf("read payload")
	msg := &BittorrentMessage{
		ID:      id,
		Payload: buf,
	}

	return msg, msg.Validate()
}

func (m *BittorrentMessage) Validate() error {

	var expectedPayloadLength = -1

	switch m.ID {
	case MsgChoke, MsgUnchoke, MsgInterested, MsgNotInterested:
		expectedPayloadLength = 0
		break
	case MsgHave:
		expectedPayloadLength = 4
		break
	case MsgRequest:
		expectedPayloadLength = 12
		break
	case MsgPiece:
		expectedPayloadLength = 8
		break
	case MsgBitfield:
		if len(m.Payload) < 1 {
			return errors.New("malformed bitfield message")
		}
		return nil
	}
	if len(m.Payload) != expectedPayloadLength {
		return errors.New("malformed message")
	}
	return nil
}
