package message

import (
	"encoding/binary"
	"errors"
	"io"
)

func SendPiece(index, begin, blockSize uint32, writer io.Writer) error {
	payload := make([]byte, 13)

	binary.BigEndian.PutUint32(payload, 9+blockSize)
	payload[4] = byte(MsgPiece)
	binary.BigEndian.PutUint32(payload[5:], index)
	binary.BigEndian.PutUint32(payload[9:], begin)

	_, err := writer.Write(payload)

	return err
}

func TryParsePiece(msg *BittorrentMessage) (index, begin uint32, err error) {
	if msg.ID != MsgPiece {
		return 0, 0, errors.New("mismatched message type")
	}
	return binary.BigEndian.Uint32(msg.Payload), binary.BigEndian.Uint32(msg.Payload[4:]), nil
}
