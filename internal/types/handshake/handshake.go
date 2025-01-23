package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const pstrlen = 19

var pstr = []byte("BitTorrent protocol")

type Handshake struct {
	InfoHash []byte
	PeerID   []byte
}

func (h *Handshake) Serialize() []byte {
	buf := [68]byte{}
	buf[0] = pstrlen
	copy(buf[1:], pstr)
	copy(buf[28:], h.InfoHash)
	copy(buf[48:], h.PeerID)
	return buf[:]
}

func Deserialize(buf []byte) (h *Handshake, err error) {
	if buf[0] != pstrlen || len(buf) != 68 || !bytes.Equal(buf[1:20], pstr) {
		return nil, errors.New("unsupported protocol")
	}

	if binary.LittleEndian.Uint64(buf[20:28]) != 0 {
		return nil, errors.New("unsupported extensions")
	}

	return &Handshake{
		InfoHash: buf[28:48],
		PeerID:   buf[48:],
	}, nil
}
