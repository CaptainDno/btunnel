package btunnel

type KeyStore interface {
	GetKey(keyID []byte) []byte
}
