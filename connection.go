package btunnel

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	handshake2 "github.com/CaptainDno/btunnel/internal/types/handshake"
	message2 "github.com/CaptainDno/btunnel/internal/types/message"
	utils2 "github.com/CaptainDno/btunnel/internal/utils"
	"go.uber.org/zap"
	"golang.org/x/exp/rand"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type SharedPeerId struct {
	id          string
	mu          sync.Mutex
	lastUpdated time.Time
}

var clients = [2]string{"qB5030", "UT3550"}

func generatePeerID() string {

	client := clients[mrand.Intn(len(clients))]

	return fmt.Sprintf("-%s-%s", client, utils2.GenerateRandomDigits(12))
}

func newSharedPeerId() *SharedPeerId {
	return &SharedPeerId{
		id:          generatePeerID(),
		lastUpdated: time.Now(),
	}
}

func (pid *SharedPeerId) GetId() string {
	pid.mu.Lock()
	if time.Now().Sub(pid.lastUpdated) > time.Hour {
		pid.id = generatePeerID()
		pid.lastUpdated = time.Now()
	}
	res := pid.id
	pid.mu.Unlock()
	return res
}

var SharedPeerID = newSharedPeerId()

const unfinishedBlockCountTarget = 500

const DefaultBlockSize = 1024 * 16       // bytes
const DefaultPieceSize = 1024 * 1024 * 4 //bytes

// Thread safety:
// It is safe to read and write simultaneously.

type Connection struct {
	// Name for logging purposes
	logger *zap.Logger

	// TCP connection
	conn net.Conn

	// Buffered reader
	reader *bufio.Reader

	// Cipher used for message encryption
	aead cipher.AEAD

	// Bittorrent specific fields:

	// So after initial handshake we do not think in actual pieces at all.
	// We just check if we should send data fragments that look like actual PIECE message headers
	// Like we have our <command>-<payload> message.
	// Last four bytes of nonce are counter based (counter resets when piece-block changes)
	// [<length>]-[<command>-<payload>]
	//     aad           encrypted
	// If payload length is > then remaining block size, we read up to the end of block, then read next PIECE header,
	// update counters etc. and then we read remaining message length

	// The values for piece and offset of last sent request
	lastRequestedPiece  uint32
	lastRequestedOffset uint32
	// Count of unfinished blocks. When it is low, new pieces should be requested to allow continuous communication
	// This is the only value that can be updated by both read and write methods, therefore needs to be atomic,
	unfinishedBlockCount atomic.Int32

	// Piece that we are currently sending
	currentTxPiece uint32
	// Current offset in this piece
	currentTxOffset uint32
	// Remaining block capacity
	remainingBlockCapacityTx uint32
	// Last 4 bytes of nonce for encryption
	cntTx uint32

	// Piece that we are currently receiving
	currentRxPiece uint32
	// And its current offset
	currentRxOffset uint32
	// Current remaining block size
	remainingBlockCapacityRx uint32
	// Last 4 bytes of nonce for decryption
	cntRx uint32

	// First piece that should be requested
	startPiece uint32
	// Last piece that can be safely requested while using current session key
	endPiece uint32

	// Block size negotiated during handshake
	blockSize uint32
	// Piece size in bytes
	pieceSize uint32

	// Set after init() is called
	isInitialized bool
	// Also some random HAVE messages should be added for noise
	// So on handshake we need to also add start piece, end piece, block size
}

const MaxPieceCount = 10000

var ProtoTcp = zap.String("proto", "tcp")
var ProtoBittorrent = zap.String("proto", "bittorrent")
var ProtoBTun = zap.String("proto", "btun")

func Connect(logger *zap.Logger, address string, keyID []byte, clientID string, keyStore KeyStore) (*Connection, error) {

	masterSecret := keyStore.GetKey(keyID)
	if masterSecret == nil {
		return nil, errors.New("no key found for key id")
	}

	if len(keyID) != 20 {
		return nil, errors.New("key id must be 20 bytes long")
	}

	logger.Info("dialing...", ProtoTcp)
	conn, err := net.DialTimeout("tcp", address, time.Second*10)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)

	logger.Info("successfully connected to server", ProtoTcp)
	// Initiate Bittorrent Handshake
	{
		h := &handshake2.Handshake{
			// Key id is info hash
			InfoHash: keyID,
			// Peer ID is configurable
			PeerID: []byte(SharedPeerID.GetId()),
		}
		_, err = conn.Write(h.Serialize())
		logger.Info("sent client handshake", ProtoBittorrent, zap.String("peer-id", string(h.PeerID)), zap.Binary("info-hash", h.InfoHash))
		if err != nil {
			return nil, err
		}

		buf := make([]byte, 68)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}

		h, err = handshake2.Deserialize(buf)

		if err != nil {
			return nil, err
		}
		logger.Info("received handshake response", ProtoBittorrent, zap.String("peer-id", string(h.PeerID)), zap.Binary("info-hash", h.InfoHash))

		if !bytes.Equal(keyID, h.InfoHash) {
			return nil, errors.New("handshake failed")
		}
		logger.Info("handshake successful", ProtoBittorrent)
	}

	// Initiate custom handshake

	var sessionGCM cipher.AEAD
	var sh *handshake2.ServerHello
	{
		// Generate session key
		sessionKey := make([]byte, 32)
		_, err = rand.Read(sessionKey)
		if err != nil {
			return nil, err
		}

		// Prepare client hello
		ch, err := handshake2.NewClientHello(clientID, ClientVersion, sessionKey)
		if err != nil {
			return nil, err
		}

		// Prepare cipher
		masterGCM, err := utils2.NewGCM(masterSecret)
		if err != nil {
			return nil, err
		}

		// Send client hello to server
		// TODO Add some randomness
		if err = ch.WriteClientHello(conn, masterGCM, DefaultBlockSize, DefaultPieceSize, 0, MaxPieceCount/2-1); err != nil {
			return nil, err
		}

		logger.Info("client hello sent", ProtoBTun, zap.Any("client-hello", ch))

		sh, err = handshake2.ReadServerHello(reader, masterGCM)
		if err != nil {
			return nil, err
		}

		logger.Info("server hello received", ProtoBTun, zap.Any("server-hello", sh))

		if !bytes.Equal(sh.AcceptedSessionKey, sessionKey) {
			return nil, errors.New("session key mismatch")
		}

		if sh.AcceptedClientID != clientID {
			return nil, errors.New("client id mismatch")
		}

		sessionGCM, err = utils2.NewGCM(sh.AcceptedSessionKey)
		if err != nil {
			return nil, err
		}

		logger.Info("handshake successful", ProtoBTun)
	}
	// Finish connection init with unchoke and interested message exchange
	logger.Info("unchoking", ProtoBittorrent)
	if err = UnchokeAndInterested(conn, reader); err != nil {
		return nil, err
	}

	connection := &Connection{
		logger:                   logger,
		conn:                     conn,
		reader:                   reader,
		aead:                     sessionGCM,
		lastRequestedPiece:       sh.FirstPiece,
		lastRequestedOffset:      0,
		unfinishedBlockCount:     atomic.Int32{},
		currentTxPiece:           0,
		currentTxOffset:          0,
		remainingBlockCapacityTx: DefaultBlockSize,
		cntTx:                    0,
		currentRxPiece:           sh.FirstPiece,
		currentRxOffset:          0,
		remainingBlockCapacityRx: DefaultBlockSize,
		cntRx:                    0,
		startPiece:               0,
		endPiece:                 MaxPieceCount/2 - 1,
		blockSize:                DefaultBlockSize,
		pieceSize:                DefaultPieceSize,
		isInitialized:            false,
	}

	// Send initial requests
	if err = connection.init(); err != nil {
		return nil, err
	}

	return connection, nil
}

type ClientIDValidator func(clientID string) bool

func Accept(logger *zap.Logger, conn net.Conn, keyStore KeyStore, validator ClientIDValidator) (*Connection, error) {
	logger.Info("accepted new connection", ProtoTcp)
	reader := bufio.NewReader(conn)

	// Wait for handshake
	var masterSecret []byte
	{
		buf := make([]byte, 68)
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			return nil, err
		}

		h, err := handshake2.Deserialize(buf)
		if err != nil {
			return nil, err
		}
		logger.Info("received handshake", ProtoBittorrent, zap.String("peer-id", string(h.PeerID)), zap.Binary("info-hash", h.InfoHash))

		// We need to find a key
		masterSecret = keyStore.GetKey(h.InfoHash)
		if masterSecret == nil {
			return nil, errors.New("no key found for provided key id")
		}

		respH := &handshake2.Handshake{
			InfoHash: h.InfoHash,
			PeerID:   []byte(SharedPeerID.GetId()),
		}
		_, err = conn.Write(respH.Serialize())

		if err != nil {
			return nil, err
		}
		logger.Info("sent response handshake", ProtoBittorrent, zap.String("peer-id", string(respH.PeerID)), zap.Binary("info-hash", respH.InfoHash))
	}

	// Wait for custom handshake - prepare master cipher for decryption
	var sessionGCM cipher.AEAD
	var firstPiece uint32
	var ch *handshake2.ClientHello
	{
		masterGCM, err := utils2.NewGCM(masterSecret)
		if err != nil {
			return nil, err
		}

		ch, err = handshake2.ReadClientHello(reader, masterGCM)
		if err != nil {
			return nil, err
		}

		if !validator(ch.ClientID) {
			return nil, errors.New("invalid client id")
		}

		logger.Info("client hello received", ProtoBTun, zap.Any("client-hello", ch))

		// Select first piece that server will send to client (and client request from server)
		firstPiece = ch.LastPiece + uint32(rand.Intn(50))

		sh, err := handshake2.FromClientHello(ch, ServerVersion, firstPiece, MaxPieceCount)
		if err != nil {
			return nil, err
		}

		if err = sh.WriteServerHello(conn, masterGCM); err != nil {
			return nil, err
		}

		logger.Info("server hello sent", ProtoBTun, zap.Any("client-hello", sh))

		sessionGCM, err = utils2.NewGCM(sh.AcceptedSessionKey)
		if err != nil {
			return nil, err
		}
		logger.Info("handshake successful", ProtoBTun)
	}

	logger.Info("unchoking", ProtoBittorrent)
	// Finish connection init with unchoke and interested message exchange
	if err := UnchokeAndInterested(conn, reader); err != nil {
		return nil, err
	}

	connection := &Connection{
		logger:                   logger,
		conn:                     conn,
		reader:                   reader,
		aead:                     sessionGCM,
		lastRequestedPiece:       ch.FirstPiece,
		lastRequestedOffset:      0,
		unfinishedBlockCount:     atomic.Int32{},
		currentTxPiece:           firstPiece,
		currentTxOffset:          0,
		remainingBlockCapacityTx: ch.BlockSize,
		cntTx:                    0,
		currentRxPiece:           ch.FirstPiece,
		currentRxOffset:          0,
		remainingBlockCapacityRx: ch.BlockSize,
		cntRx:                    0,
		startPiece:               firstPiece,
		endPiece:                 MaxPieceCount,
		blockSize:                ch.BlockSize,
		pieceSize:                ch.PieceSize,
	}

	if err := connection.init(); err != nil {
		return nil, err
	}

	return connection, nil
}

func UnchokeAndInterested(writer io.Writer, reader io.Reader) error {
	// Send unchoke and interested
	{
		msg := message2.BittorrentMessage{
			ID:      message2.MsgUnchoke,
			Payload: message2.EmptyPayload,
		}
		if err := msg.Write(writer); err != nil {
			return err
		}

		msg.ID = message2.MsgInterested
		if err := msg.Write(writer); err != nil {
			return err
		}
	}

	// Wait for unchoke and interested (in this order)
	{
		msg, err := message2.Read(reader)

		if err != nil {
			return err
		}

		if msg.ID != message2.MsgUnchoke {
			return errors.New("expected UNCHOKE message, got something different")
		}

		msg, err = message2.Read(reader)

		if err != nil {
			return err
		}

		if msg.ID != message2.MsgInterested {
			return errors.New("expected INTERESTED message, got something different")
		}

	}
	return nil
}

// Prepare connection to handle actual traffic
func (conn *Connection) init() error {
	conn.logger.Info("performing final initialization...", ProtoBTun)
	if err := conn.requestBlocks(); err != nil {
		return err
	}

	if err := message2.SendPiece(conn.startPiece, 0, conn.blockSize, conn.conn); err != nil {
		return err
	}

	if err := conn.handleBittorrentMessages(); err != nil {
		return err
	}
	conn.isInitialized = true
	conn.logger.Info("connection is ready for use", ProtoBTun)
	return nil
}

// requestBlocks
// If unfinished blocks count is lower than target, sends REQUEST messages.
// Updates connection state:
//
//	lastRequestedPiece
//	lastRequestedOffset
//	unfinishedBlockCount
func (conn *Connection) requestBlocks() error {
	conn.logger.Debug("requesting blocks", ProtoBittorrent)
	var err error

	// We use buffer to speed up the whole process
	buf := new(bytes.Buffer)
	currUBC := conn.unfinishedBlockCount.Load()
	buf.Grow(int(message2.PieceMessageByteLength * (unfinishedBlockCountTarget - currUBC)))

	// If connection is uninitialized, first block in first piece is available
	if !conn.isInitialized {
		err = message2.SendRequest(conn.lastRequestedPiece, conn.lastRequestedOffset, conn.blockSize, buf)
		if err != nil {
			return err
		}
		currUBC++
	}
	for currUBC < unfinishedBlockCountTarget {
		newOffset := conn.lastRequestedOffset + conn.blockSize
		newPiece := conn.lastRequestedPiece
		if newOffset >= conn.pieceSize {
			newPiece += 1
			newOffset = 0
		}

		err = message2.SendRequest(newPiece, newOffset, conn.blockSize, buf)
		if err != nil {
			break
		}

		conn.lastRequestedPiece = newPiece
		conn.lastRequestedOffset = newOffset
		currUBC++
	}
	conn.unfinishedBlockCount.Store(currUBC)
	// Send whole buffer
	_, err = conn.conn.Write(buf.Bytes())
	return err
}

func (conn *Connection) WriteMessage(payload []byte) error {
	// One nonce will be used to encrypt whole message
	// TODO !note: even if remainingBlockCapacity == 0, CURRENT state is used in nonce!
	nonce := make([]byte, 12)

	binary.BigEndian.PutUint32(nonce, conn.currentTxPiece)
	binary.BigEndian.PutUint32(nonce[4:], conn.currentTxOffset)
	binary.BigEndian.PutUint32(nonce[8:], conn.cntTx)

	// 4 leading bytes for length
	cipherText := make([]byte, 4)
	cipherText = conn.aead.Seal(cipherText, nonce, payload, nil)

	// Put length
	binary.BigEndian.PutUint32(cipherText, uint32(len(cipherText)-4))

	bytesToSend := uint32(len(cipherText))
	pos := uint32(0)

	conn.logger.Debug("sending message", ProtoBTun,
		zap.Uint32("len", bytesToSend),
		zap.Uint32("capacity", conn.remainingBlockCapacityTx),
		zap.Binary("nonce", nonce),
	)

	// We cannot write whole payload + len field to current block. Splitting is needed
	// Remember! Length field may be fragmented too - that is completely normal
	for bytesToSend > conn.remainingBlockCapacityTx {
		// Write everything we can
		written, err := conn.conn.Write(cipherText[pos : pos+conn.remainingBlockCapacityTx])
		if err != nil {
			return err
		}
		pos += uint32(written)
		bytesToSend -= uint32(written)

		// TODO Unfinished blocks are consumed when we read from connection, but we can't send REQUEST message when there is ongoing PIECE transmission
		// TODO We need a way to force end of piece transmission.
		// Send requests while we can
		err = conn.requestBlocks()
		if err != nil {
			return err
		}

		// Prepare to shift to new block

		newOffset := conn.currentTxOffset + conn.blockSize
		// Reset counter, because we are now in new block
		conn.cntTx = 0
		conn.remainingBlockCapacityTx = conn.blockSize

		newPiece := conn.currentTxPiece
		// Handle next piece
		if newOffset >= conn.pieceSize {
			newPiece = conn.currentTxPiece + 1
			if newPiece > conn.endPiece {
				return errors.New("last piece reached")
			}
			newOffset = 0
		}

		// Send PIECE message
		if err = message2.SendPiece(newPiece, newOffset, conn.blockSize, conn.conn); err != nil {
			return err
		}
		conn.currentTxOffset = newOffset
		conn.currentTxPiece = newPiece
		conn.logger.Debug("shifted to next block while writing message", ProtoBittorrent, zap.Uint32("index", newPiece), zap.Uint32("offset", newOffset))
	}

	// Here everything is simple - just write data and update counter
	_, err := conn.conn.Write(cipherText[pos:])
	if err != nil {
		return err
	}
	conn.cntTx++
	conn.remainingBlockCapacityTx -= bytesToSend
	return nil
}

// ReadMessage reads next message from connection
func (conn *Connection) ReadMessage() ([]byte, error) {
	if conn.unfinishedBlockCount.Load() < 5 {
		conn.logger.Warn("low amount of unfinished blocks", ProtoBittorrent, zap.Int("count", int(conn.unfinishedBlockCount.Load())))
	}
	// Prepare nonce for the whole message
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce, conn.currentRxPiece)
	binary.BigEndian.PutUint32(nonce[4:], conn.currentRxOffset)
	binary.BigEndian.PutUint32(nonce[8:], conn.cntRx)
	conn.logger.Debug("reading message", ProtoBTun,
		zap.Binary("nonce", nonce),
	)
	// Read length
	lenBuf := make([]byte, 4)
	err := conn.readFragmented(lenBuf)
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)

	// Read cipher text
	payload := make([]byte, length)
	err = conn.readFragmented(payload)
	if err != nil {
		return nil, err
	}
	// Decrypt
	payload, err = conn.aead.Open(payload[:0], nonce, payload, nil)
	if err != nil {
		return nil, err
	}
	// Increment count of received messages
	conn.cntRx++
	return payload, nil
}

// Close closes the underlying TCP connection, rendering this struct useless
// Note: it is not safe to call Close when either ReadMessage or WriteMessage may be called by other goroutines.
func (conn *Connection) Close() error {
	conn.logger.Info("closing connection", ProtoTcp)
	return conn.conn.Close()
}

func (conn *Connection) readFragmented(buf []byte) error {
	bytesToRead := uint32(len(buf))
	conn.logger.Debug("read fragmented", ProtoBTun, zap.Uint32("len", bytesToRead), zap.Uint32("block-capacity", conn.remainingBlockCapacityRx))
	pos := uint32(0)

	for bytesToRead > conn.remainingBlockCapacityRx {
		// Read what we can
		read, err := io.ReadFull(conn.reader, buf[pos:pos+conn.remainingBlockCapacityRx])
		if err != nil {
			return err
		}
		pos += uint32(read)
		bytesToRead -= uint32(read)
		// Read Bittorrent messages until we receive next PIECE message
		if err = conn.handleBittorrentMessages(); err != nil {
			return err
		}
	}

	// Simple read

	_, err := io.ReadFull(conn.reader, buf[pos:])
	if err != nil {
		return err
	}

	conn.remainingBlockCapacityRx -= bytesToRead
	// Here we cannot update cntRx, because that counter is for whole messages and not just bytes
	return nil
}

// Handles all bittorrent traffic until PIECE is encountered
func (conn *Connection) handleBittorrentMessages() error {
	for {
		msg, err := message2.Read(conn.reader)
		if err != nil {
			return err
		}

		index, begin, length, err := message2.TryParseRequest(msg)
		if err == nil {
			conn.logger.Debug("handled bittorrent message", ProtoBittorrent, zap.String("type", "request"), zap.Uint32("index", index), zap.Uint32("begin", begin), zap.Uint32("length", length))
			continue
		}

		index, begin, err = message2.TryParsePiece(msg)
		if err == nil {

			// Validate
			if index < conn.currentRxPiece {
				return errors.New("new piece index is smaller than current. this may result in catastrophic cryptographic failure")
			}

			if index == conn.currentRxPiece {
				if conn.isInitialized {
					if begin <= conn.currentRxOffset {
						return errors.New("new offset is smaller than current. this may result in catastrophic cryptographic failure")
					}
					if begin-conn.currentRxOffset != conn.blockSize {
						return errors.New("offset delta is not equal to block size")
					}
				}

			}

			if begin%conn.blockSize != 0 {
				return errors.New("offset is not divisible by block size")
			}

			if begin > conn.pieceSize {
				return errors.New("offset too large")
			}

			// Update connection state and exit loop

			conn.currentRxPiece = index
			conn.currentRxOffset = begin
			conn.cntRx = 0
			conn.remainingBlockCapacityRx = conn.blockSize
			conn.unfinishedBlockCount.Add(-1)
			conn.logger.Debug("handled bittorrent message", ProtoBittorrent, zap.String("type", "piece"), zap.Uint32("index", index), zap.Uint32("begin", begin))
			break
		}

		conn.logger.Debug("ignored bittorrent message", ProtoBittorrent, zap.String("type", "irrelevant"), zap.Int("id", int(msg.ID)))
	}
	return nil
}
