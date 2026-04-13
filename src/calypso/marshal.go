package calypso

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/blspairing"
)

// bufPool provides a reusable pool of bytes.Buffer for serialization
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// marshalSlotSalt serializes a SlotSalt
// Format (big-endian): [Value_len(4)|Value|N_len(4)|N]
func marshalSlotSalt(salt *SlotSalt) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	valueBytes := salt.Value.Bytes()
	binary.Write(buf, binary.BigEndian, uint32(len(valueBytes)))
	buf.Write(valueBytes)

	nBytes := salt.N.Bytes()
	binary.Write(buf, binary.BigEndian, uint32(len(nBytes)))
	buf.Write(nBytes)

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// unmarshalSlotSalt deserializes a SlotSalt
func unmarshalSlotSalt(data []byte) (*SlotSalt, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("slot salt data too short")
	}

	salt := &SlotSalt{}
	offset := 0

	valueLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(valueLen) > len(data) {
		return nil, fmt.Errorf("invalid Value length")
	}
	salt.Value = new(big.Int).SetBytes(data[offset : offset+int(valueLen)])
	offset += int(valueLen)

	if offset+4 > len(data) {
		return nil, fmt.Errorf("slot salt data too short for N length")
	}
	nLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(nLen) != len(data) {
		return nil, fmt.Errorf("invalid N length")
	}
	salt.N = new(big.Int).SetBytes(data[offset : offset+int(nLen)])

	return salt, nil
}

// marshalSlot serializes a Slot
// Format (big-endian): [Type(1)|Index(4)|Label_len(2)|Label|Prime_len(4)|Prime|Salt_len(4)|Salt|Value_len(2)|Value]
// Prime, Salt, Value may be zero-length (nil fields)
func marshalSlot(slot *Slot) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	// Type
	buf.WriteByte(byte(slot.Type))

	// Index
	binary.Write(buf, binary.BigEndian, uint32(slot.Index))

	// Label
	labelBytes := []byte(slot.Label)
	binary.Write(buf, binary.BigEndian, uint16(len(labelBytes)))
	buf.Write(labelBytes)

	// Prime
	var primeBytes []byte
	if slot.Prime != nil {
		primeBytes = slot.Prime.Bytes()
	}
	binary.Write(buf, binary.BigEndian, uint32(len(primeBytes)))
	if len(primeBytes) > 0 {
		buf.Write(primeBytes)
	}

	// Salt
	var saltBytes []byte
	if slot.Salt != nil {
		var err error
		saltBytes, err = marshalSlotSalt(slot.Salt)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Salt: %w", err)
		}
	}
	binary.Write(buf, binary.BigEndian, uint32(len(saltBytes)))
	if len(saltBytes) > 0 {
		buf.Write(saltBytes)
	}

	// Value
	var valueBytes []byte
	if slot.Value != nil {
		valueBytes = blspairing.ScalarToBytes(slot.Value)
	}
	binary.Write(buf, binary.BigEndian, uint16(len(valueBytes)))
	if len(valueBytes) > 0 {
		buf.Write(valueBytes)
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// unmarshalSlot deserializes a Slot
func unmarshalSlot(data []byte) (*Slot, error) {
	if len(data) < 1+4+2+4+4+2 {
		return nil, fmt.Errorf("slot data too short")
	}

	slot := &Slot{}
	offset := 0

	// Type
	slot.Type = SlotType(data[offset])
	offset++

	// Index
	slot.Index = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Label
	labelLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(labelLen) > len(data) {
		return nil, fmt.Errorf("invalid Label length")
	}
	slot.Label = string(data[offset : offset+int(labelLen)])
	offset += int(labelLen)

	// Prime
	if offset+4 > len(data) {
		return nil, fmt.Errorf("slot data too short for Prime length")
	}
	primeLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if primeLen > 0 {
		if offset+int(primeLen) > len(data) {
			return nil, fmt.Errorf("invalid Prime length")
		}
		slot.Prime = new(big.Int).SetBytes(data[offset : offset+int(primeLen)])
		offset += int(primeLen)
	}

	// Salt
	if offset+4 > len(data) {
		return nil, fmt.Errorf("slot data too short for Salt length")
	}
	saltLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if saltLen > 0 {
		if offset+int(saltLen) > len(data) {
			return nil, fmt.Errorf("invalid Salt length")
		}
		salt, err := unmarshalSlotSalt(data[offset : offset+int(saltLen)])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal Salt: %w", err)
		}
		slot.Salt = salt
		offset += int(saltLen)
	}

	// Value
	if offset+2 > len(data) {
		return nil, fmt.Errorf("slot data too short for Value length")
	}
	valueLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if valueLen > 0 {
		if offset+int(valueLen) != len(data) {
			return nil, fmt.Errorf("invalid Value length")
		}
		slot.Value = new(bls.Scalar)
		if err := slot.Value.UnmarshalBinary(data[offset : offset+int(valueLen)]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Value: %w", err)
		}
	}

	return slot, nil
}

// marshalLabelSecret serializes a LabelSecret
// Format (big-endian): [SK_len(4)|SK_PKCS8|Totient_len(4)|Totient|Value_len(4)|Value]
func marshalLabelSecret(ls *LabelSecret) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	// Serialize RSA private key to PKCS8
	skBytes, err := x509.MarshalPKCS8PrivateKey(ls.SK)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA key: %w", err)
	}

	binary.Write(buf, binary.BigEndian, uint32(len(skBytes)))
	buf.Write(skBytes)

	totientBytes := ls.Totient.Bytes()
	binary.Write(buf, binary.BigEndian, uint32(len(totientBytes)))
	buf.Write(totientBytes)

	valueBytes := ls.Value.Bytes()
	binary.Write(buf, binary.BigEndian, uint32(len(valueBytes)))
	buf.Write(valueBytes)

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// unmarshalLabelSecret deserializes a LabelSecret
func unmarshalLabelSecret(data []byte) (*LabelSecret, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("label secret data too short")
	}

	ls := &LabelSecret{}
	offset := 0

	// SK
	skLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(skLen) > len(data) {
		return nil, fmt.Errorf("invalid SK length")
	}
	skAny, err := x509.ParsePKCS8PrivateKey(data[offset : offset+int(skLen)])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}
	var ok bool
	ls.SK, ok = skAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA private key")
	}
	offset += int(skLen)

	// Totient
	if offset+4 > len(data) {
		return nil, fmt.Errorf("label secret data too short for Totient length")
	}
	totientLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(totientLen) > len(data) {
		return nil, fmt.Errorf("invalid Totient length")
	}
	ls.Totient = new(big.Int).SetBytes(data[offset : offset+int(totientLen)])
	offset += int(totientLen)

	// Value
	if offset+4 > len(data) {
		return nil, fmt.Errorf("label secret data too short for Value length")
	}
	valueLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(valueLen) != len(data) {
		return nil, fmt.Errorf("invalid Value length")
	}
	ls.Value = new(big.Int).SetBytes(data[offset : offset+int(valueLen)])

	return ls, nil
}

// MarshalBinary implements encoding.BinaryMarshaler for Message
// Format (all multi-byte integers in big-endian):
// [SearchTag_len(2)|SearchTag|WrappedKey_len(4)|WrappedKey|
//
//	IV(16)|Ciphertext_len(4)|Ciphertext|Signature_len(4)|Signature]
func (msg *Message) MarshalBinary() ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	// SearchTag
	searchTagBytes := []byte(msg.SearchTag)
	binary.Write(buf, binary.BigEndian, uint16(len(searchTagBytes)))
	buf.Write(searchTagBytes)

	// WrappedKey
	wrappedKeyBytes, err := msg.WrappedKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize WrappedKey: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(wrappedKeyBytes)))
	buf.Write(wrappedKeyBytes)

	// IV (fixed 16 bytes)
	buf.Write(msg.IV)

	// Ciphertext
	binary.Write(buf, binary.BigEndian, uint32(len(msg.Ciphertext)))
	buf.Write(msg.Ciphertext)

	// Signature
	sigBytes, err := msg.Signature.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Signature: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(sigBytes)))
	buf.Write(sigBytes)

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Message
func (msg *Message) UnmarshalBinary(data []byte) error {
	if len(data) < 2+4+16+4+4 {
		return fmt.Errorf("message data too short")
	}

	offset := 0

	// SearchTag
	searchTagLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(searchTagLen) > len(data) {
		return fmt.Errorf("invalid SearchTag length")
	}
	msg.SearchTag = string(data[offset : offset+int(searchTagLen)])
	offset += int(searchTagLen)

	// WrappedKey
	if offset+4 > len(data) {
		return fmt.Errorf("message data too short for WrappedKey length")
	}
	wrappedKeyLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(wrappedKeyLen) > len(data) {
		return fmt.Errorf("invalid WrappedKey length")
	}
	msg.WrappedKey = &akn07.Ciphertext{}
	if err := msg.WrappedKey.UnmarshalBinary(data[offset : offset+int(wrappedKeyLen)]); err != nil {
		return fmt.Errorf("failed to deserialize WrappedKey: %w", err)
	}
	offset += int(wrappedKeyLen)

	// IV (fixed 16 bytes)
	if offset+16 > len(data) {
		return fmt.Errorf("message data too short for IV")
	}
	msg.IV = make([]byte, 16)
	copy(msg.IV, data[offset:offset+16])
	offset += 16

	// Ciphertext
	if offset+4 > len(data) {
		return fmt.Errorf("message data too short for Ciphertext length")
	}
	ciphertextLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(ciphertextLen) > len(data) {
		return fmt.Errorf("invalid Ciphertext length")
	}
	msg.Ciphertext = make([]byte, ciphertextLen)
	copy(msg.Ciphertext, data[offset:offset+int(ciphertextLen)])
	offset += int(ciphertextLen)

	// Signature
	if offset+4 > len(data) {
		return fmt.Errorf("message data too short for Signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(sigLen) != len(data) {
		return fmt.Errorf("invalid Signature length")
	}
	msg.Signature = &akn07.Signature{}
	if err := msg.Signature.UnmarshalBinary(data[offset : offset+int(sigLen)]); err != nil {
		return fmt.Errorf("failed to deserialize Signature: %w", err)
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler for Authority
// Format (big-endian): [MasterKey_len(4)|MasterKey|PublicParams_len(4)|PublicParams|
//
//	NumSecrets(2)|LabelSecret_0|...|LabelSecret_N]
func (auth *Authority) MarshalBinary() ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	// MasterKey
	mkBytes, err := auth.MasterKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize MasterKey: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(mkBytes)))
	buf.Write(mkBytes)

	// PublicParams
	ppBytes, err := auth.PublicParams.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicParams: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(ppBytes)))
	buf.Write(ppBytes)

	// NumSecrets
	binary.Write(buf, binary.BigEndian, uint16(len(auth.LabelSecrets)))

	// LabelSecrets - write directly without intermediate slice
	for i, ls := range auth.LabelSecrets {
		lsBytes, err := marshalLabelSecret(ls)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize LabelSecret %d: %w", i, err)
		}
		binary.Write(buf, binary.BigEndian, uint32(len(lsBytes)))
		buf.Write(lsBytes)
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for Authority
func (auth *Authority) UnmarshalBinary(data []byte) error {
	if len(data) < 4+4+2 {
		return fmt.Errorf("authority data too short")
	}

	offset := 0

	// MasterKey
	mkLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(mkLen) > len(data) {
		return fmt.Errorf("invalid MasterKey length")
	}
	auth.MasterKey = &akn07.MasterKey{}
	if err := auth.MasterKey.UnmarshalBinary(data[offset : offset+int(mkLen)]); err != nil {
		return fmt.Errorf("failed to deserialize MasterKey: %w", err)
	}
	offset += int(mkLen)

	// PublicParams
	if offset+4 > len(data) {
		return fmt.Errorf("authority data too short for PublicParams length")
	}
	ppLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(ppLen) > len(data) {
		return fmt.Errorf("invalid PublicParams length")
	}
	auth.PublicParams = &akn07.PublicParams{}
	if err := auth.PublicParams.UnmarshalBinary(data[offset : offset+int(ppLen)]); err != nil {
		return fmt.Errorf("failed to deserialize PublicParams: %w", err)
	}
	offset += int(ppLen)

	// NumSecrets
	if offset+2 > len(data) {
		return fmt.Errorf("authority data too short for NumSecrets")
	}
	numSecrets := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// LabelSecrets
	auth.LabelSecrets = make([]*LabelSecret, numSecrets)
	for i := 0; i < int(numSecrets); i++ {
		if offset+4 > len(data) {
			return fmt.Errorf("authority data too short for LabelSecret %d length", i)
		}
		lsLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		if offset+int(lsLen) > len(data) {
			return fmt.Errorf("invalid LabelSecret %d length", i)
		}
		ls, err := unmarshalLabelSecret(data[offset : offset+int(lsLen)])
		if err != nil {
			return fmt.Errorf("failed to deserialize LabelSecret %d: %w", i, err)
		}
		auth.LabelSecrets[i] = ls
		offset += int(lsLen)
	}

	if offset != len(data) {
		return fmt.Errorf("authority data has unexpected trailing bytes")
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler for PrivateKey
// Format (big-endian): [PublicParams_len(4)|PublicParams|SK_len(4)|SK|
//
//	DomainName_len(2)|DomainName|SearchTag_len(2)|SearchTag|
//	NumSlots(2)|Slot_0|...|Slot_N]
func (key *PrivateKey) MarshalBinary() ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() { buf.Reset(); bufPool.Put(buf) }()

	// PublicParams
	ppBytes, err := key.PublicParams.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PublicParams: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(ppBytes)))
	buf.Write(ppBytes)

	// SK
	skBytes, err := key.SK.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SK: %w", err)
	}
	binary.Write(buf, binary.BigEndian, uint32(len(skBytes)))
	buf.Write(skBytes)

	// DomainName
	domainNameBytes := []byte(key.DomainName)
	binary.Write(buf, binary.BigEndian, uint16(len(domainNameBytes)))
	buf.Write(domainNameBytes)

	// SearchTag
	searchTagBytes := []byte(key.SearchTag)
	binary.Write(buf, binary.BigEndian, uint16(len(searchTagBytes)))
	buf.Write(searchTagBytes)

	// NumSlots
	binary.Write(buf, binary.BigEndian, uint16(len(key.Slots)))

	// Slots - write directly without intermediate slice
	for i, slot := range key.Slots {
		sb, err := marshalSlot(slot)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Slot %d: %w", i, err)
		}
		binary.Write(buf, binary.BigEndian, uint32(len(sb)))
		buf.Write(sb)
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for PrivateKey
func (key *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) < 4+4+2+2+2 {
		return fmt.Errorf("private key data too short")
	}

	offset := 0

	// PublicParams
	ppLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(ppLen) > len(data) {
		return fmt.Errorf("invalid PublicParams length")
	}
	key.PublicParams = &akn07.PublicParams{}
	if err := key.PublicParams.UnmarshalBinary(data[offset : offset+int(ppLen)]); err != nil {
		return fmt.Errorf("failed to deserialize PublicParams: %w", err)
	}
	offset += int(ppLen)

	// SK
	if offset+4 > len(data) {
		return fmt.Errorf("private key data too short for SK length")
	}
	skLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(skLen) > len(data) {
		return fmt.Errorf("invalid SK length")
	}
	key.SK = &akn07.PrivateKey{}
	if err := key.SK.UnmarshalBinary(data[offset : offset+int(skLen)]); err != nil {
		return fmt.Errorf("failed to deserialize SK: %w", err)
	}
	offset += int(skLen)

	// DomainName
	if offset+2 > len(data) {
		return fmt.Errorf("private key data too short for DomainName length")
	}
	domainNameLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(domainNameLen) > len(data) {
		return fmt.Errorf("invalid DomainName length")
	}
	key.DomainName = string(data[offset : offset+int(domainNameLen)])
	offset += int(domainNameLen)

	// SearchTag
	if offset+2 > len(data) {
		return fmt.Errorf("private key data too short for SearchTag length")
	}
	searchTagLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(searchTagLen) > len(data) {
		return fmt.Errorf("invalid SearchTag length")
	}
	key.SearchTag = string(data[offset : offset+int(searchTagLen)])
	offset += int(searchTagLen)

	// NumSlots
	if offset+2 > len(data) {
		return fmt.Errorf("private key data too short for NumSlots")
	}
	numSlots := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Slots
	key.Slots = make([]*Slot, numSlots)
	for i := 0; i < int(numSlots); i++ {
		if offset+4 > len(data) {
			return fmt.Errorf("private key data too short for Slot %d length", i)
		}
		slotLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		if offset+int(slotLen) > len(data) {
			return fmt.Errorf("invalid Slot %d length", i)
		}
		slot, err := unmarshalSlot(data[offset : offset+int(slotLen)])
		if err != nil {
			return fmt.Errorf("failed to deserialize Slot %d: %w", i, err)
		}
		key.Slots[i] = slot
		offset += int(slotLen)
	}

	if offset != len(data) {
		return fmt.Errorf("private key data has unexpected trailing bytes")
	}

	return nil
}
