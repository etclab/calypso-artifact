package main

// CryptoType represents the encryption scheme used
type CryptoType byte

const (
	// NoOp represents plaintext (no encryption)
	NoOp CryptoType = 0x00
	// AES represents AES-256-GCM encryption
	AES CryptoType = 0x01
	// WKDIBE represents WKD-IBE encryption using akn07 scheme
	WKDIBE CryptoType = 0x02
	// Calypso represents Calypso encryption with mandatory signatures
	Calypso CryptoType = 0x03
)

// String returns the name of the crypto type
func (ct CryptoType) String() string {
	switch ct {
	case NoOp:
		return "NoOp"
	case AES:
		return "AES"
	case WKDIBE:
		return "WKDIBE"
	case Calypso:
		return "Calypso"
	default:
		return "Unknown"
	}
}