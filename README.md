This package provides a way to make encrypted tcp traffic look **similar** to Bittorrent connection.

## Considerations

+ This is experimental package, mainly intended for use in my other projects. 
+ Symmetric encryption is used for initial handshake. Remember, DO NOT share keys between clients.
  Otherwise, they will be able to intercept and decrypt handshake message where session key is agreed upon.

## How it works

Bittorrent handshake is emulated, InfoHash is used to transmit `KeyID`. `KeyID` MUST be 20 bytes in length. After that client and server hello are disguised as BitField messages
from BitTorrent protocol. Client and server negotiate block size, piece size, "file" size, session encryption key etc.

After that, both client and server will send `REQUEST` and `PIECE` messages as if they download parts of the torrent from each other.

*Note: sending of `REQUEST` messages is triggered only from `WriteMessage()` function. This means that sometimes it may seem like peer is sending unrequested `PIECE` messages
which is not allowed by BittorrentSpec. This happens if client very rarely writes.* 

## Thread safety (VERY IMPORTANT)

Safe scenario: two goroutines, one handles only writes and one only reads. Reads and writes may happen simultaneously

UNSAFE scenario: multiple goroutines call `ReadMessage` or `WriteMessage` without some synchronization like mutex.

**REMEMBER!** Race conditions may cause nonce repetition, which is **disastrous** for encryption algorithm used by this library.

## Usage
Reads from connection are buffered, writes are not. May change in the future.

Use [btunnel-proxy](https://github.com/CaptainDno/btunnel-proxy) as a  working example.
