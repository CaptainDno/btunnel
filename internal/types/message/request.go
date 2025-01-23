package message

import (
	"encoding/binary"
	"errors"
	"io"
)

const PieceMessageByteLength = 17

func SendRequest(index, begin, length uint32, writer io.Writer) error {
	payload := make([]byte, 12)

	binary.BigEndian.PutUint32(payload, index)
	binary.BigEndian.PutUint32(payload[4:], begin)
	binary.BigEndian.PutUint32(payload[8:], length)

	msg := BittorrentMessage{
		ID:      MsgRequest,
		Payload: payload,
	}

	return msg.Write(writer)
}

func TryParseRequest(msg *BittorrentMessage) (index, begin, length uint32, err error) {
	if msg.ID != MsgRequest {
		return 0, 0, 0, errors.New("mismatched message type")
	}

	return binary.BigEndian.Uint32(msg.Payload), binary.BigEndian.Uint32(msg.Payload[4:]), binary.BigEndian.Uint32(msg.Payload[8:]), nil
}
