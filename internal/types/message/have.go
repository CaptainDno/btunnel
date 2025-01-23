package message

import (
	"encoding/binary"
	"errors"
	"io"
)

func WriteHave(index uint32, writer io.Writer) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, index)

	msg := BittorrentMessage{
		ID:      MsgHave,
		Payload: payload,
	}
	return msg.Write(writer)
}

func TryParseHave(msg *BittorrentMessage) (index uint32, err error) {
	if msg.ID != MsgHave {
		return 0, errors.New("wrong message type")
	}

	return binary.BigEndian.Uint32(msg.Payload), nil
}
