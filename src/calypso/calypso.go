package calypso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"

	"github.com/etclab/mu"
	"github.com/etclab/ncircl/acc/bdm93"
	"github.com/etclab/ncircl/hibe/akn07"
	"github.com/etclab/ncircl/util/aesx"
	"github.com/etclab/ncircl/util/blspairing"
	"github.com/etclab/ncircl/util/bytesx"

	"golang.org/x/crypto/hkdf"
)

const (
	rsaModulusBits  = 3072
	MaxLabelLen     = 63
	WildcardLabel   = "*"
	TerminatorLabel = "$"
	ReaderLabel     = "&"
	IvLength        = 16
)

var (
	bigOne = big.NewInt(1)

	ErrInvalidSignature  = errors.New("calypso: Invalid signature")
	ErrInvalidDomainName = errors.New("calypso: Invalid domain name")
	ErrHasWildcard       = errors.New("calypso: The pattern has a wildcard")
	ErrKeyIsNotAWriter   = errors.New("calypso: The key is not a writer key")
)

// isConcreteDomainName returns true if domainName does not have any labels
// that are the wildcard symbol, the terminator symbol, or the empty string.
func isConcreteDomainName(domainName string) bool {
	labels := strings.Split(domainName, ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if label == WildcardLabel {
			return false
		}
		if label == TerminatorLabel {
			return false
		}
		if label == "" {
			return false
		}
	}
	return true
}

// domainNameToReverseLabels takes a domainName and returns a slice of its
// labels in reverse order.  For instance, for a domainName of "com.a.b", it
// returns ["b", "a", "com"].  The domainName can include wildcards, such as
// "com.a.*", "com.*.b", or "com.a.*.*".
//
// The function returns an error if domainName has more labels than the maximum
// depth - 2 (to leave room for a terminator and a signature).  The function also returns an
// error if domainName
// - has no labels (i.e., is an empty string)
// - has a label that is an empty string
// - has a label where len(label) > MaxLabelLen
// - has a label that is the terminator symbol ("$")
func domainNameToReverseLabels(pp *akn07.PublicParams, domainName string) ([]string, error) {
	labels := strings.Split(domainName, ".")
	slices.Reverse(labels)
	if (len(labels) + 2) > pp.MaxDepth {
		return nil, akn07.ErrPatternExceedsMaxDepth
	}
	if len(labels) == 0 {
		return nil, ErrInvalidDomainName
	}

	for _, label := range labels {
		if len(label) > MaxLabelLen {
			return nil, ErrInvalidDomainName
		}
		if label == TerminatorLabel {
			return nil, ErrInvalidDomainName
		}
		if label == "" {
			return nil, ErrInvalidDomainName
		}
	}

	return labels, nil
}

type LabelSecret struct {
	SK      *rsa.PrivateKey
	Totient *big.Int // Totient = (P-1)*(Q-1)
	Value   *big.Int
}

func NewLabelSecret() *LabelSecret {
	var err error

	ls := new(LabelSecret)
	ls.SK, err = rsa.GenerateKey(rand.Reader, rsaModulusBits)
	if err != nil {
		mu.BUG("rsa.GenerateKey failed: %v", err)
	}

	p := ls.SK.Primes[0]
	q := ls.SK.Primes[1]

	pminus1 := new(big.Int).Sub(p, bigOne)
	qminus1 := new(big.Int).Sub(q, bigOne)
	ls.Totient = new(big.Int).Mul(pminus1, qminus1)

	ls.Value = big.NewInt(65537) // g (base)
	return ls
}

type Authority struct {
	MasterKey    *akn07.MasterKey
	PublicParams *akn07.PublicParams
	LabelSecrets []*LabelSecret
}

func NewAuthority(maxDepth int) *Authority {
	auth := new(Authority)
	auth.PublicParams, auth.MasterKey = akn07.Setup(maxDepth)

	auth.LabelSecrets = make([]*LabelSecret, maxDepth-1)
	for i := 0; i < maxDepth-1; i++ {
		auth.LabelSecrets[i] = NewLabelSecret()
	}

	return auth
}

func cloneBigInt(x *big.Int) *big.Int {
	return new(big.Int).Set(x)
}

type SlotSalt struct {
	// Value is the salt's value
	Value *big.Int

	// N is the salt's RSA modulus
	N *big.Int
}

func NewSlotSalt(value *big.Int, modulus *big.Int) *SlotSalt {
	salt := new(SlotSalt)
	salt.Value = cloneBigInt(value)
	salt.N = cloneBigInt(modulus)
	return salt
}

func (salt *SlotSalt) Clone() *SlotSalt {
	newSalt := new(SlotSalt)
	newSalt.Value = cloneBigInt(salt.Value)
	newSalt.N = cloneBigInt(salt.N)
	return newSalt
}

// SlotType is an enum-like value that indicates the logical type for a pattern
// slot
type SlotType int

const (
	// SlotTypeUnused represents a pattern slot that is not used
	SlotTypeUnused SlotType = iota

	// SlotTypeLabel represents a pattern slot that is a DNS label
	SlotTypeLabel

	// SlotTypeWildcard represents a pattern slot that is the "*" wildcard label
	SlotTypeWildcard

	// SlotTypeTerminator represents a pattern slot that has the "$" terminator
	// label.  This internal label represents the end of the domain name.
	SlotTypeTerminator

	// SlotTypeSignature represents a pattern slot that is used for computing a
	// signature.  This is always the last slot and is mutually exclusive with
	// SlotTypeReader.  Note: A slot of type SlotTypeSignature does not have a
	// salt.
	SlotTypeSignature

	// SlotTypeSignature represents a pattern slot that indicates that the
	// pattnern is for reading data, not publishing data.  This is always the
	// last slot and is mutually exclusive with SlotTypeSignature.  Note: A
	// slot of type SlotTypeReader does not have a salt.
	SlotTypeReader
)

// String returns a string corresponding to the SlotType
func (st SlotType) String() string {
	switch st {
	case SlotTypeUnused:
		return "unused"
	case SlotTypeLabel:
		return "label"
	case SlotTypeWildcard:
		return "wildcard"
	case SlotTypeTerminator:
		return "terminator"
	case SlotTypeSignature:
		return "signature"
	case SlotTypeReader:
		return "reader"
	default:
		mu.BUG("uknown SlotType: %v", st)
	}

	return "unknown" // appease compiler
}

// Slot contains the metadata value for a pattern slot, as well as that slot's
// pattern value
type Slot struct {
	// Type is the slot type
	Type SlotType

	// The index (0-based) in the reverse domain name
	Index int

	// Label is the DNS label
	Label string

	// Prime is the slot's contribution to its own salt and to the salt of all
	// subsequent slots.  For SlotTypeWildcard slots, Prime is nil.
	Prime *big.Int

	// Salt is the slot's current salt value
	Salt *SlotSalt

	// Value is the slot's pattern value.  Not that Value is nil until all
	// previous slots and this slot itself are not wildcards.
	Value *bls.Scalar
}

func NewUnusedSlot(index int) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeUnused
	slot.Index = index
	return slot
}

func NewLabelSlot(index int, label string, labelSecret *LabelSecret) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeLabel
	slot.Index = index
	slot.Label = label
	slot.Salt = NewSlotSalt(labelSecret.Value, labelSecret.SK.N)
	slot.Prime = hashLabelToPrime(index, label)
	return slot
}

func NewWildcardSlot(index int, labelSecret *LabelSecret) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeWildcard
	slot.Index = index
	slot.Label = WildcardLabel
	slot.Salt = NewSlotSalt(labelSecret.Value, labelSecret.SK.N)
	return slot
}

func NewTerminatorSlot(index int, labelSecret *LabelSecret) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeTerminator
	slot.Index = index
	slot.Label = TerminatorLabel
	slot.Salt = NewSlotSalt(labelSecret.Value, labelSecret.SK.N)
	slot.Prime = hashLabelToPrime(index, TerminatorLabel)
	return slot
}

func NewReaderSlot(index int) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeReader
	slot.Index = index
	slot.Label = ReaderLabel
	slot.Value = blspairing.HashBytesToScalar([]byte(ReaderLabel))
	return slot
}

func NewSignatureSlot(index int) *Slot {
	slot := new(Slot)
	slot.Type = SlotTypeSignature
	slot.Index = index
	return slot
}

func convertWildcardSlotToLabel(slot *Slot, newLabel string) {
	if slot.Type != SlotTypeWildcard {
		mu.BUG("slot is not a wildcard, but type %s", slot.Type)
	}
	slot.Type = SlotTypeLabel
	// index stays the same
	slot.Label = newLabel
	slot.Prime = hashLabelToPrime(slot.Index, newLabel)
	slot.UpdateSalt(slot.Prime)
	// value is lazily computed
}

func convertWildcardSlotToTerminator(slot *Slot) {
	if slot.Type != SlotTypeWildcard {
		mu.BUG("slot is not a wildcard, but type %s", slot.Type)
	}
	slot.Type = SlotTypeTerminator
	// index stays the same
	slot.Label = TerminatorLabel
	slot.Prime = hashLabelToPrime(slot.Index, TerminatorLabel)
	slot.UpdateSalt(slot.Prime)
	// value is lazily computed
}

func convertWildcardSlotToUnused(slot *Slot) {
	if slot.Type != SlotTypeWildcard {
		mu.BUG("slot is not a wildcard, but type %s", slot.Type)
	}
	slot.Type = SlotTypeUnused
	// index stays the same
	slot.Label = ""
	slot.Prime = nil
	slot.Salt = nil
	slot.Value = nil
}

// String returns a string representation of a Slot.
func (slot *Slot) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "slot {\n")
	fmt.Fprintf(&sb, "    Type: %v,\n", slot.Type)
	fmt.Fprintf(&sb, "    Index: %d,\n", slot.Index)
	fmt.Fprintf(&sb, "    Label: %q,\n", slot.Label)
	fmt.Fprintf(&sb, "    Prime: %v,\n", slot.Prime)
	if slot.Salt != nil {
		fmt.Fprintf(&sb, "    Salt: {\n")
		fmt.Fprintf(&sb, "        Value: %v\n", slot.Salt.Value)
		fmt.Fprintf(&sb, "        N: %v\n", slot.Salt.N)
		fmt.Fprintf(&sb, "    }\n")
	}
	fmt.Fprintf(&sb, "    Value: %v,\n", slot.Value)
	fmt.Fprintf(&sb, "}\n")
	return sb.String()
}

// Clone returns a deep copy of a Slot.
func (slot *Slot) Clone() *Slot {
	newSlot := new(Slot)
	newSlot.Type = slot.Type
	newSlot.Index = slot.Index
	newSlot.Label = slot.Label
	if slot.Prime != nil {
		newSlot.Prime = cloneBigInt(slot.Prime)
	}
	if slot.Salt != nil {
		newSlot.Salt = slot.Salt.Clone()
	}
	if slot.Value != nil {
		newSlot.Value = blspairing.CloneScalar(slot.Value)
	}
	return newSlot
}

// UpdateSalt updates a salt's value by raising it to prime and then taking
// the result modulo the salt's modulus.
func (slot *Slot) UpdateSalt(prime *big.Int) {
	slot.Salt.Value.Exp(slot.Salt.Value, prime, slot.Salt.N)
}

// AutoComputeValue computes and sets the slot's pattern value.
func (slot *Slot) AutoComputeValue() {
	hkdfer := hkdf.New(sha256.New, slot.Salt.Value.Bytes(), nil, []byte(slot.Label))
	tmpBuf := make([]byte, 32)
	_, err := io.ReadFull(hkdfer, tmpBuf)
	if err != nil {
		mu.Fatalf("io.ReadFull failed: %v", err)
	}
	slot.Value = blspairing.HashBytesToScalar(tmpBuf)
}

func cloneSlots(slots []*Slot) []*Slot {
	newSlots := make([]*Slot, len(slots))
	for i, slot := range slots {
		newSlots[i] = slot.Clone()
	}
	return newSlots
}

func slotsToPattern(slots []*Slot) *akn07.Pattern {
	pattern := new(akn07.Pattern)
	pattern.Ps = make([]*bls.Scalar, len(slots))
	for i, slot := range slots {
		pattern.Ps[i] = slot.Value
	}
	return pattern
}

// createSearchTag creates the tag for the key's underlying domain name.
// User's can use the serach tag to lookup the domain name without revealing
// what the domain name is.
func createSearchTag(slots []*Slot) (string, error) {
	// The search tag includes from the start of the pattern through the first
	// terminator slot. It is an error if the tag includes a wildcard slot.
	h := sha256.New()
	for i := 0; i < len(slots)-1; i++ {
		if slots[i].Type == SlotTypeWildcard {
			return "", ErrHasWildcard
		}

		if slots[i].Type == SlotTypeTerminator {
			h.Write(blspairing.ScalarToBytes(slots[i].Value))
			break
		}

		h.Write(blspairing.ScalarToBytes(slots[i].Value))
	}

	digest := h.Sum(nil)
	return hex.EncodeToString(digest), nil
}

// hashLabelToPrime hashes a label to an odd prime.  The function
// concatenates the label's slot index with the label itself before hashing.
func hashLabelToPrime(slotIndex int, domainLabel string) *big.Int {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(slotIndex))
	buf = append(buf, []byte(domainLabel)...)
	return bdm93.HashToPrime(buf)
}

type PrivateKey struct {
	PublicParams *akn07.PublicParams
	SK           *akn07.PrivateKey
	DomainName   string
	Slots        []*Slot
	SearchTag    string
	// TODO: add cache of child keys
}

func (key *PrivateKey) String() string {
	var labels []string
	for _, slot := range key.Slots {
		if slot.Type == SlotTypeSignature {
			labels = append(labels, "σ")
		} else if slot.Type == SlotTypeUnused {
			labels = append(labels, "X")
		} else {
			labels = append(labels, slot.Label)
		}
	}
	return fmt.Sprintf("domain=%s, writer=%t, slots=%s", key.DomainName, key.IsWriter(), strings.Join(labels, "."))
}

func (key *PrivateKey) DebugString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "PrivateKey {\n")
	fmt.Fprintf(&sb, "\tDomainName: %s,\n", key.DomainName)
	fmt.Fprintf(&sb, "\tSearchTag: %s,\n", key.SearchTag)
	fmt.Fprintf(&sb, "\tSK: { \n")
	fmt.Fprintf(&sb, "\t\tPattern: { \n")
	fmt.Fprintf(&sb, "\t\t\tPs: [\n")
	for i, p := range key.SK.Pattern.Ps {
		fmt.Fprintf(&sb, "\t\t\t\t%d: %v,\n", i, p)
	}
	fmt.Fprintf(&sb, "\t\t\t]\n")
	fmt.Fprintf(&sb, "\t\t}\n")
	fmt.Fprintf(&sb, "\t}\n")
	fmt.Fprintf(&sb, "\tSlots: [\n")
	for i, slot := range key.Slots {
		fmt.Fprintf(&sb, "\t\t%d: {\n", i)
		fmt.Fprintf(&sb, "\t\t\tType: %v,\n", slot.Type)
		fmt.Fprintf(&sb, "\t\t\tIndex: %d,\n", slot.Index)
		fmt.Fprintf(&sb, "\t\t\tLabel: %q,\n", slot.Label)
		fmt.Fprintf(&sb, "\t\t\tPrime: %v,\n", slot.Prime)
		if slot.Salt != nil {
			fmt.Fprintf(&sb, "\t\t\tSalt: {\n")
			fmt.Fprintf(&sb, "\t\t\t\tValue: %v\n", slot.Salt.Value)
			fmt.Fprintf(&sb, "\t\t\t\tN: %v\n", slot.Salt.N)
			fmt.Fprintf(&sb, "\t\t\t}\n")
		}
		fmt.Fprintf(&sb, "\t\t\tValue: %v,\n", slot.Value)
		fmt.Fprintf(&sb, "\t\t}\n")
	}
	fmt.Fprintf(&sb, "\t]\n")
	fmt.Fprintf(&sb, "}\n")

	return sb.String()
}

// IsWriter returns whether a key is a writer.  A writer key is one that can
// produce signatures.
func (key *PrivateKey) IsWriter() bool {
	return key.Slots[len(key.Slots)-1].Type == SlotTypeSignature
}

// CanDerive returns true if the key can derive other keys.  A key can derive
// child keys if it has a wildcard before a terminator slot.
func (key *PrivateKey) CanDerive() bool {
	foundWildcard := false
	foundTerminator := false
	for _, slot := range key.Slots {
		if slot.Type == SlotTypeWildcard {
			foundWildcard = true
			break
		}
		if slot.Type == SlotTypeTerminator {
			foundTerminator = true
			break
		}
	}
	return foundWildcard && !foundTerminator
}

// Clone returns a deep copy of a PrivateKey
func (key *PrivateKey) Clone() *PrivateKey {
	slots := make([]*Slot, len(key.Slots))
	for i := 0; i < len(slots); i++ {
		slots[i] = key.Slots[i].Clone()
	}

	return &PrivateKey{
		PublicParams: key.PublicParams.Clone(),
		SK:           key.SK.Clone(),
		DomainName:   key.DomainName,
		Slots:        slots,
	}
}

func (auth *Authority) domainNameToSlots(domainName string, isWriter bool) ([]*Slot, error) {
	pp := auth.PublicParams

	labels, err := domainNameToReverseLabels(pp, domainName)
	if err != nil {
		return nil, err
	}

	// initialize the specified slots
	hasWildcard := false
	slots := make([]*Slot, pp.MaxDepth)
	for i, label := range labels {
		if label == WildcardLabel {
			hasWildcard = true
			slots[i] = NewWildcardSlot(i, auth.LabelSecrets[i])
		} else {
			slots[i] = NewLabelSlot(i, label, auth.LabelSecrets[i])
		}
	}

	// initialize the trailing (non-specified) slot
	i := len(labels)
	slots[i] = NewTerminatorSlot(i, auth.LabelSecrets[i])

	// initailize the unused slots between the terminator and the last slot
	for i := len(labels) + 1; i < len(slots)-1; i++ {
		slots[i] = NewUnusedSlot(i)
	}

	// initialize the signer/reader last slot
	if isWriter {
		slots[len(slots)-1] = NewSignatureSlot(i)
	} else {
		slots[len(slots)-1] = NewReaderSlot(i)
	}

	// Update the salts for all used slots (except last one---the signature/reader
	// slot---which doesn't have a salt).
	acc := cloneBigInt(bigOne)
	for i := 0; i < len(slots)-1; i++ {
		if slots[i].Type == SlotTypeUnused {
			break
		}
		if slots[i].Type == SlotTypeLabel || slots[i].Type == SlotTypeTerminator {
			acc.Mul(acc, slots[i].Prime)
		}
		var x big.Int
		x.Mod(acc, auth.LabelSecrets[i].Totient)
		slots[i].UpdateSalt(&x)
	}

	// Compute the pattern value for all labeled slots up to the first
	// non-label slot.  These are the slots that have a fully-computed salt.
	for _, slot := range slots {
		if slot.Type != SlotTypeLabel {
			break
		}
		slot.AutoComputeValue()
	}

	// If there are no wildcards, then finalize the slots by computing the
	// value of the terminator slot
	if !hasWildcard {
		slots[len(labels)].AutoComputeValue()
	}

	return slots, nil
}

func (auth *Authority) IssueKey(domainName string, isWriter bool) (*PrivateKey, error) {
	slots, err := auth.domainNameToSlots(domainName, isWriter)
	if err != nil {
		return nil, err
	}

	pattern := slotsToPattern(slots)
	sk, err := akn07.KeyGen(auth.PublicParams, auth.MasterKey, pattern)
	if err != nil {
		return nil, err
	}

	key := &PrivateKey{
		PublicParams: auth.PublicParams.Clone(),
		SK:           sk,
		DomainName:   domainName,
		Slots:        slots,
	}

	if !key.CanDerive() {
		key.SearchTag, err = createSearchTag(slots)
		if err != nil {
			mu.BUG("createSearchTag failed: %v", err)
		}
	}

	return key, nil
}

// reverseLabelsMatch returns true if the childLabels match the parent labels.
// A match means:
//  1. the child must not have a greater number of labels than the parent
//  2. if the parent specifies a non-wildcard label the child
//     must have the same label.
func reverseLabelsMatch(parentLabels, childLabels []string) bool {
	if len(childLabels) > len(parentLabels) {
		return false
	}

	for i := 0; i < len(childLabels); i++ {
		if (childLabels[i] != parentLabels[i]) && (parentLabels[i] != WildcardLabel) {
			return false
		}
	}

	// If the child has few labels than the parent, then all trailing labels in
	// the parent must be a wildcard.  This is a corollary of condition (2).

	if len(childLabels) < len(parentLabels) {
		for i := len(childLabels); i < len(parentLabels); i++ {
			if parentLabels[i] != WildcardLabel {
				return false
			}
		}
	}

	return true
}

func (key *PrivateKey) domainNameToSlots(domainName string, isWriter bool) ([]*Slot, error) {
	pp := key.PublicParams

	childLabels, err := domainNameToReverseLabels(pp, domainName)
	if err != nil {
		return nil, err
	}

	parentLabels, err := domainNameToReverseLabels(pp, key.DomainName)
	if err != nil {
		mu.BUG("domainNameToReverseLabels failed for valid key with pp.MaxDepth=%d and domain name: %q", pp.MaxDepth, key.DomainName)
	}

	if !reverseLabelsMatch(parentLabels, childLabels) {
		return nil, akn07.ErrPatternDoesNotMatch
	}

	childSlots := cloneSlots(key.Slots)

	// If we filled in any wildcard slots, we need to compute the prime for
	// that wildcard, and then update all salts starting at that wildcard
	// down to (but not including) the signature/reader slot
	foundUnfilledWildcard := false
	for i, childLabel := range childLabels {
		if key.Slots[i].Label != childLabel {
			if key.Slots[i].Type == SlotTypeWildcard {
				convertWildcardSlotToLabel(childSlots[i], childLabel)
				for j := i + 1; j < len(childSlots)-1; j++ {
					if childSlots[j].Type == SlotTypeUnused {
						break
					}
					childSlots[j].UpdateSalt(childSlots[i].Prime)
				}
				if !foundUnfilledWildcard {
					// if we just filled in a wildcard, and there are no
					// wildcards before this slot, then its salt is finalized
					// and we can compute its slot pattern value.
					childSlots[i].AutoComputeValue()
				}
			} else {
				mu.BUG("child domain (%q) should match parent (%q)", domainName, key.DomainName)
			}
		} else if key.Slots[i].Type == SlotTypeWildcard {
			foundUnfilledWildcard = true
		}
	}

	// if the child has fewer labels than the parent, the trailing parent labels
	// must have been wildcards.  Set these to a terminator label and then
	// unusued labels in the child
	if len(childLabels) < len(parentLabels) {
		convertWildcardSlotToTerminator(childSlots[len(childLabels)])
		for i := len(childLabels) + 1; i < len(parentLabels); i++ {
			convertWildcardSlotToUnused(childSlots[i])
		}
	}

	// If the parent was a writer, but the derived key is a reader, change the
	// last slot
	if key.IsWriter() && !isWriter {
		childSlots[len(childSlots)-1] = NewReaderSlot(len(childSlots) - 1)
	}

	// If there are no wildcard slots, then make sure all slots up to and
	// including the terminator slot have a value.
	hasWildcard := false
	for _, slot := range childSlots {
		if slot.Type == SlotTypeTerminator {
			break
		}
		if slot.Type == SlotTypeWildcard {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		for _, slot := range childSlots {
			if slot.Value == nil {
				slot.AutoComputeValue()
			}
			if slot.Type == SlotTypeTerminator {
				break
			}
		}
	}

	return childSlots, nil
}

func (key *PrivateKey) DeriveKey(domainName string, isWriter bool) (*PrivateKey, error) {
	// TODO: change to use cache
	if !key.IsWriter() && isWriter {
		return nil, ErrKeyIsNotAWriter
	}

	childSlots, err := key.domainNameToSlots(domainName, isWriter)
	if err != nil {
		return nil, err
	}

	childPattern := slotsToPattern(childSlots)
	childSK, err := akn07.KeyDer(key.PublicParams, key.SK, childPattern)
	if err != nil {
		return nil, err
	}

	childKey := &PrivateKey{
		PublicParams: key.PublicParams.Clone(),
		SK:           childSK,
		DomainName:   domainName,
		Slots:        childSlots,
	}

	if !childKey.CanDerive() {
		childKey.SearchTag, err = createSearchTag(childSlots)
		if err != nil {
			mu.BUG("createSearchTag failed: %v", err)
		}
	}

	return childKey, nil
}

// DeriverReader returns a reader key for the same pattern as the key on which
// this method was invoked.  If that key was not writer, then the function
// returns an error.
func (key *PrivateKey) DeriveReader() (*PrivateKey, error) {
	if !key.IsWriter() {
		return nil, ErrKeyIsNotAWriter
	}

	childSlots := cloneSlots(key.Slots)
	childSlots[len(childSlots)-1] = NewReaderSlot(len(childSlots) - 1)

	childPattern := slotsToPattern(childSlots)
	childSK, err := akn07.KeyDer(key.PublicParams, key.SK, childPattern)
	if err != nil {
		return nil, err
	}

	childKey := &PrivateKey{
		PublicParams: key.PublicParams.Clone(),
		SK:           childSK,
		DomainName:   key.DomainName,
		Slots:        childSlots,
	}

	if !childKey.CanDerive() {
		childKey.SearchTag, err = createSearchTag(childSlots)
		if err != nil {
			mu.BUG("createSearchTag failed: %v", err)
		}
	}

	return childKey, nil
}

type Message struct {
	// SearchTag is the lookup tag (a hex string).
	SearchTag string

	// WrappedKey is the encryption of a Gt element from which the AES key is
	// derived.
	WrappedKey *akn07.Ciphertext

	// IV is the initialization vector for AES-CTR encryption.
	IV []byte

	// Ciphertext is the AES-CTR encrypted plaintext message.
	Ciphertext []byte

	// Signature is the WKD-IBE signaure of the plaintext message.
	Signature *akn07.Signature
}

func encrypt(key *PrivateKey, plaintext []byte) (*Message, error) {
	m := blspairing.NewRandomGt()
	aesKey := blspairing.KdfGtToAes256(m)
	iv := bytesx.Random(IvLength)
	ciphertext, err := aesx.EncryptCTR(aesKey, iv, plaintext)
	if err != nil {
		return nil, err
	}

	wrappedKey, err := akn07.Encrypt(key.PublicParams, key.SK.Pattern, m)
	if err != nil {
		return nil, err
	}

	message := &Message{
		SearchTag:  key.SearchTag,
		WrappedKey: wrappedKey,
		IV:         iv,
		Ciphertext: ciphertext,
	}

	return message, nil
}

func sign(key *PrivateKey, plaintext []byte) *akn07.Signature {
	hashPlaintext := blspairing.HashBytesToScalar(plaintext)
	sig := akn07.Sign(key.PublicParams, key.SK, hashPlaintext)
	return sig
}

func (key *PrivateKey) EncryptAndSign(domainName string, plaintext []byte) (*Message, error) {
	var err error
	var signingKey *PrivateKey

	if !key.IsWriter() {
		return nil, ErrKeyIsNotAWriter
	}

	if !isConcreteDomainName(domainName) {
		return nil, ErrInvalidDomainName
	}

	if key.DomainName == domainName {
		signingKey = key
	} else {
		signingKey, err = key.DeriveKey(domainName, true)
		if err != nil {
			return nil, err
		}
	}

	encryptingKey, err := signingKey.DeriveReader()
	if err != nil {
		return nil, err
	}

	//log.Printf("signing key: %s\n", signingKey.DebugString())
	//log.Printf("encrypting key: %s\n", encryptingKey.DebugString())

	// N.B. we sign first because key.encrypt overwrites the plaintxt slice
	signature := sign(signingKey, plaintext)
	message, err := encrypt(encryptingKey, plaintext)
	if err != nil {
		return nil, err
	}
	message.Signature = signature

	return message, nil
}

func decrypt(key *PrivateKey, message *Message) ([]byte, error) {
	m := akn07.Decrypt(key.PublicParams, key.SK, message.WrappedKey)
	aesKey := blspairing.KdfGtToAes256(m)
	plaintext, err := aesx.DecryptCTR(aesKey, message.IV, message.Ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func verify(key *PrivateKey, plaintext []byte, signature *akn07.Signature) error {
	hashPlaintext := blspairing.HashBytesToScalar(plaintext)
	verifyPattern := key.SK.Pattern.Clone()
	verifyPattern.Ps[len(verifyPattern.Ps)-1] = nil
	//log.Printf("verifying key: %s\n", key.DebugString())
	valid := akn07.Verify(key.PublicParams, verifyPattern, signature, hashPlaintext)
	if !valid {
		return ErrInvalidSignature
	}
	return nil
}

func (key *PrivateKey) DecryptAndVerify(domainName string, message *Message) ([]byte, error) {
	var err error
	var decryptingKey *PrivateKey

	if !isConcreteDomainName(domainName) {
		return nil, ErrInvalidDomainName
	}

	if key.DomainName == domainName {
		if key.IsWriter() {
			decryptingKey, err = key.DeriveReader()
			if err != nil {
				return nil, err
			}
		} else {
			decryptingKey = key
		}
	} else {
		decryptingKey, err = key.DeriveKey(domainName, false)
		if err != nil {
			return nil, err
		}
	}

	//log.Printf("decrypting key: %s\n", decryptingKey.DebugString())

	plaintext, err := decrypt(decryptingKey, message)
	if err != nil {
		return nil, err
	}

	//log.Printf("DecryptAndVerify: got plaintext: %q\n", string(plaintext))

	err = verify(decryptingKey, plaintext, message.Signature)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
