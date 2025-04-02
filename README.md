This package provides a way to make tcp traffic look similar to Bittorrent connection.

Additional description and documentation will be added after active development finishes.

Considerations:
* This is experimental package, mainly intended for use in my other projects.
* Mimicking is done on best effort basis. This means, that Bittorrent protocol may be violated to some extent if it is needed to maintain acceptable connection speed.
* Symmetric encryption is used for initial handshake. Remember, DO NOT share keys between clients. 
   Otherwise, they will be able to intercept and decrypt handshake message, where session key is agreed upon.