package calypso

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/etclab/ncircl/util/bytesx"
)

func Test_domainNameToReverseLabels(t *testing.T) {
	auth := NewAuthority(7)
	pp := auth.PublicParams

	longLabel := strings.Repeat("b", 64)

	trials := []struct {
		domainName string
		hasError   bool
		revLabels  []string
	}{
		{"com", false, []string{"com"}},
		{"a.com", false, []string{"com", "a"}},
		{"b.a.com", false, []string{"com", "a", "b"}},
		{"c.b.a.com", false, []string{"com", "a", "b", "c"}},
		{"d.c.b.a.com", false, []string{"com", "a", "b", "c", "d"}},

		{"", true, nil},                   // no labels
		{"a..coma", true, nil},            // label that is an empty string
		{longLabel + ".a.com", true, nil}, // label where len(label) > // MaxLabelLen
		{"$.a.com", true, nil},            // label that is the blocked symbol ("$")
		{"e.d.c.b.a.com", true, nil},      // number of labels + 2 >  number of slots
		{"f.e.d.c.b.a.com", true, nil},    // number of labels + 2 > number of slot
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("domainName=%s", trial.domainName), func(t *testing.T) {
			got, err := domainNameToReverseLabels(pp, trial.domainName)
			if trial.hasError && err == nil {
				t.Fatalf("trial %q expected an error but got a success", trial.domainName)
			}
			if !trial.hasError && err != nil {
				t.Fatalf("trial %q expected a success but got an error: %v", trial.domainName, err)
			}
			if trial.hasError {
				return
			}
			if !slices.Equal(got, trial.revLabels) {
				t.Fatalf("trial %q expected %v labels but got %v", trial.domainName, trial.revLabels, got)
			}
		})
	}
}

func Test_reverseLabelsMatch(t *testing.T) {
	trials := []struct {
		parentLabels []string
		childLabels  []string
		expected     bool
	}{
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a"},
			true,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "b"},
			true,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "b", "*"},
			true,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "*", "c"},
			true,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "b", "c"},
			true,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "b"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "b", "c"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "*", "b", "c"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "b", "c", "*"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "*", "*", "d"},
			false,
		},
		{
			[]string{"com", "a", "*", "*"},
			[]string{"com", "a", "b", "c", "d"},
			false,
		},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("parentLabels=%s/childLabels=%s", strings.Join(trial.parentLabels, "."), strings.Join(trial.childLabels, ".")), func(t *testing.T) {
			got := reverseLabelsMatch(trial.parentLabels, trial.childLabels)
			if got != trial.expected {
				t.FailNow()
			}
		})
	}
}

func TestPrivateKey_IsWriter(t *testing.T) {
	auth := NewAuthority(7)

	rKey, err := auth.IssueKey("a.com", false)
	if err != nil {
		t.Fatalf("auth.IssueKey(\"a.com\", false) failed: %v", err)
	}
	if rKey.IsWriter() {
		t.Error("IsWriter() returned true for a reader key")
	}

	wKey, err := auth.IssueKey("a.com", true)
	if err != nil {
		t.Fatalf("auth.IssueKey(\"a.com\", true) failed: %v", err)
	}
	if !wKey.IsWriter() {
		t.Error("IsWriter() returned false for a writer key")
	}
}

func TestPrivateKey_CanDerive(t *testing.T) {
	auth := NewAuthority(7)

	trials := []struct {
		domainName        string
		isWriter          bool
		expectedCanDerive bool
	}{
		{"com", true, false},
		{"com", false, false},

		{"*.com", true, true},
		{"*.com", false, true},

		{"b.*.com", true, true},
		{"b.*.com", false, true},

		{"*.*.com", true, true},
		{"*.*.com", false, true},

		{"*.c.*.*.com", true, true},
		{"*.c.*.*.com", false, true},

		{"d.c.b.a.com", true, false},
		{"d.c.b.a.com", false, false},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("domainName=%s/isWriter=%t", trial.domainName, trial.isWriter), func(t *testing.T) {
			key, err := auth.IssueKey(trial.domainName, trial.isWriter)
			if err != nil {
				t.Fatalf("auth.IssueKey(%q, %t) failed: %v", trial.domainName, trial.isWriter, err)
			}
			got := key.CanDerive()
			if got != trial.expectedCanDerive {
				t.Fatalf("CanDerive: expected %t, but got %t for domainName=%q, isWriter=%t", trial.expectedCanDerive, got, trial.domainName, trial.isWriter)
			}
		})
	}
}

func TestPrivateKey_DeriveKey(t *testing.T) {
	auth := NewAuthority(7)

	parentKey, err := auth.IssueKey("*.*.a.com", true)
	if err != nil {
		t.Fatalf("auth.IssueKey(\"*.*.a.com\", true) failed: %v", err)
	}

	trials := []struct {
		childDomainName   string
		isWriter          bool
		expectedCanDerive bool
		expectedError     bool
	}{
		// successes
		{"a.com", true, false, false},
		{"a.com", false, false, false},

		{"b.a.com", true, false, false},
		{"b.a.com", false, false, false},

		{"*.b.a.com", true, true, false},
		{"*.b.a.com", false, true, false},

		{"c.*.a.com", true, true, false},
		{"c.*.a.com", false, true, false},

		{"c.b.a.com", true, false, false},
		{"c.b.a.com", false, false, false},

		// errors
		{"com", true, false, true},
		{"com", false, false, true},

		{"b.com", true, false, true},
		{"b.com", false, false, true},

		{"c.b.com", true, false, true},
		{"c.b.com", false, false, true},

		{"c.b.*.com", true, true, true},
		{"c.b.*.com", false, true, true},

		{"*.c.b.a.com", true, true, true},
		{"*.c.b.a.com", false, true, true},

		{"d.*.*.a.com", true, true, true},
		{"d.*.*.a.com", false, true, true},

		{"d.c.b.a.com", true, false, true},
		{"d.c.b.a.com", false, false, true},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("childDomainName=%s/isWriter=%t", trial.childDomainName, trial.isWriter), func(t *testing.T) {
			childKey, err := parentKey.DeriveKey(trial.childDomainName, trial.isWriter)
			if err != nil && trial.expectedError {
				return
			}
			if err != nil && !trial.expectedError {
				t.Fatalf("expected DeriveKey to succeed, but it failed: %v", err)
			}
			if err == nil && trial.expectedError {
				t.Fatal("expected DeriveKey to fail, but it succeeded")
			}

			got := childKey.CanDerive()
			if got != trial.expectedCanDerive {
				t.Fatalf("expected childKey.CanDerive() to return %t but got %t", trial.expectedCanDerive, got)
			}

			if childKey.DomainName != trial.childDomainName {
				t.Fatalf("expected childKey.DomainName=%q but got %q", trial.childDomainName, childKey.DomainName)
			}
		})
	}
}

func TestPrivateKey_DeriveReader(t *testing.T) {
	auth := NewAuthority(7)

	trials := []struct {
		domainName        string
		isWriter          bool
		expectedCanDerive bool
		expectedError     bool
	}{
		{"a.com", true, false, false},
		{"a.com", false, false, true},

		{"*.a.com", true, true, false},
		{"*.a.com", false, true, true},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("domainName=%s/isWriter=%t", trial.domainName, trial.isWriter), func(t *testing.T) {
			key, err := auth.IssueKey(trial.domainName, trial.isWriter)
			if err != nil {
				t.Fatalf("auth.IssueKey(%q, %t) failed: %v", trial.domainName, trial.isWriter, err)
			}

			readerKey, err := key.DeriveReader()
			if err != nil && trial.expectedError {
				return
			}
			if err != nil && !trial.expectedError {
				t.Fatalf("key.DeriveReader failed: %v", err)
			}
			if err == nil && trial.expectedError {
				t.Fatalf("key.DeriverReader succeeded, but expected it to fail")
			}

			got := readerKey.CanDerive()
			if got != trial.expectedCanDerive {
				t.Fatalf("expected readerKey.DeriveReader to return %t but got %t", trial.expectedCanDerive, got)
			}

			if readerKey.DomainName != key.DomainName {
				t.Fatalf("expected readerKey.DomainName (%q) to equal key.DomainName (%q)", readerKey.DomainName, key.DomainName)

			}
		})
	}
}

func TestPrivateKey_EncryptAndSign(t *testing.T) {
	plaintext := "The quick brown fox jumps over the lazy dog."
	auth := NewAuthority(7)

	trials := []struct {
		writerDomainName  string
		messageDomainName string
		readerDomainName  string
	}{
		{"a.com", "a.com", "a.com"},
		{"*.com", "a.com", "a.com"},
		{"*.com", "a.com", "*.com"},

		{"*.*.com", "a.com", "a.com"},
		{"*.*.com", "a.com", "*.com"},
		{"*.*.com", "a.com", "*.*.com"},
		{"*.*.com", "a.com", "*.a.com"},

		{"*.*.com", "b.a.com", "b.a.com"},
		{"*.*.com", "b.a.com", "b.*.com"}, // failing (crashes)
		{"*.*.com", "b.a.com", "*.a.com"},
		{"*.*.com", "b.a.com", "*.*.com"},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("writer=%s/message=%s/reader=%s", trial.writerDomainName, trial.messageDomainName, trial.readerDomainName), func(t *testing.T) {
			writerKey, err := auth.IssueKey(trial.writerDomainName, true)
			if err != nil {
				t.Fatalf("auth.IssueKey(%q, true) failed: %v", trial.writerDomainName, err)
			}
			readerKey, err := auth.IssueKey(trial.readerDomainName, false)
			if err != nil {
				t.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.readerDomainName, err)
			}

			msg, err := writerKey.EncryptAndSign(trial.messageDomainName, []byte(plaintext))
			if err != nil {
				t.Fatalf("EncryptAndSign(%q) failed: %v", trial.messageDomainName, err)
			}

			got, err := readerKey.DecryptAndVerify(trial.messageDomainName, msg)
			if err != nil {
				t.Fatalf("DecryptAndVerify(%q) failed: %v", trial.messageDomainName, err)
			}

			gotStr := string(got)
			if gotStr != plaintext {
				t.Fatalf("expected to decrypt to %q, but got %q", plaintext, gotStr)
			}
		})
	}
}

func Test_marshalUnmarshalSlotSalt(t *testing.T) {
	// Create a test SlotSalt
	value := big.NewInt(123456789)
	modulus := big.NewInt(987654321)
	salt := NewSlotSalt(value, modulus)

	// Marshal
	data, err := marshalSlotSalt(salt)
	if err != nil {
		t.Fatalf("marshalSlotSalt failed: %v", err)
	}

	// Unmarshal
	salt2, err := unmarshalSlotSalt(data)
	if err != nil {
		t.Fatalf("unmarshalSlotSalt failed: %v", err)
	}

	// Verify
	if salt.Value.Cmp(salt2.Value) != 0 {
		t.Errorf("Value mismatch: got %v, want %v", salt2.Value, salt.Value)
	}
	if salt.N.Cmp(salt2.N) != 0 {
		t.Errorf("N mismatch: got %v, want %v", salt2.N, salt.N)
	}
}

func TestMessage_MarshalUnmarshal(t *testing.T) {
	auth := NewAuthority(7)
	writerKey, err := auth.IssueKey("a.com", true)
	if err != nil {
		t.Fatalf("auth.IssueKey failed: %v", err)
	}

	originalPlaintext := []byte("Test message for serialization")
	plaintext := make([]byte, len(originalPlaintext))
	copy(plaintext, originalPlaintext)

	msg, err := writerKey.EncryptAndSign("a.com", plaintext)
	if err != nil {
		t.Fatalf("EncryptAndSign failed: %v", err)
	}

	// Marshal
	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Unmarshal
	msg2 := &Message{}
	if err := msg2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// Verify round-trip decryption
	readerKey, err := auth.IssueKey("a.com", false)
	if err != nil {
		t.Fatalf("auth.IssueKey failed: %v", err)
	}

	decrypted, err := readerKey.DecryptAndVerify("a.com", msg2)
	if err != nil {
		t.Fatalf("DecryptAndVerify failed: %v", err)
	}

	if !slices.Equal(decrypted, originalPlaintext) {
		t.Fatalf("Decrypted plaintext mismatch:\ngot:  %q (%d bytes)\nwant: %q (%d bytes)", string(decrypted), len(decrypted), string(originalPlaintext), len(originalPlaintext))
	}
}

func TestAuthority_MarshalUnmarshal(t *testing.T) {
	auth := NewAuthority(7)

	// Marshal
	data, err := auth.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Unmarshal
	auth2 := &Authority{}
	if err := auth2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	// Verify by issuing keys from both authorities
	key1, err := auth.IssueKey("test.com", true)
	if err != nil {
		t.Fatalf("auth.IssueKey failed: %v", err)
	}

	key2, err := auth2.IssueKey("test.com", true)
	if err != nil {
		t.Fatalf("auth2.IssueKey failed: %v", err)
	}

	// Keys should produce identical messages
	plaintext := []byte("test")
	msg1, err := key1.EncryptAndSign("test.com", plaintext)
	if err != nil {
		t.Fatalf("key1.EncryptAndSign failed: %v", err)
	}

	// key2 should be able to decrypt msg1
	_, err = key2.DecryptAndVerify("test.com", msg1)
	if err != nil {
		t.Fatalf("key2.DecryptAndVerify failed: %v", err)
	}
}

func TestPrivateKey_MarshalUnmarshal(t *testing.T) {
	auth := NewAuthority(7)

	trials := []struct {
		domainName        string
		isWriter          bool
		testMessageDomain string // Domain to use for encryption (must be concrete)
		testChildDomain   string // Domain to use for child derivation
	}{
		{"a.com", true, "a.com", ""},
		{"a.com", false, "", ""},
		{"*.com", true, "a.com", "a.com"},
		{"*.com", false, "", "a.com"},
		{"*.*.com", true, "a.b.com", "a.b.com"},
	}

	for _, trial := range trials {
		t.Run(fmt.Sprintf("%s/writer=%t", trial.domainName, trial.isWriter), func(t *testing.T) {
			key, err := auth.IssueKey(trial.domainName, trial.isWriter)
			if err != nil {
				t.Fatalf("auth.IssueKey failed: %v", err)
			}

			// Marshal
			data, err := key.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			// Unmarshal
			key2 := &PrivateKey{}
			if err := key2.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}

			// Verify properties
			if key2.DomainName != key.DomainName {
				t.Errorf("DomainName mismatch: got %q, want %q", key2.DomainName, key.DomainName)
			}
			if key2.SearchTag != key.SearchTag {
				t.Errorf("SearchTag mismatch: got %q, want %q", key2.SearchTag, key.SearchTag)
			}
			if len(key2.Slots) != len(key.Slots) {
				t.Fatalf("Slots count mismatch: got %d, want %d", len(key2.Slots), len(key.Slots))
			}

			// For writer keys, test encryption/decryption round-trip
			if trial.isWriter && trial.testMessageDomain != "" {
				plaintext := []byte("serialization test")
				msg, err := key2.EncryptAndSign(trial.testMessageDomain, plaintext)
				if err != nil {
					t.Fatalf("key2.EncryptAndSign failed: %v", err)
				}

				readerKey, err := auth.IssueKey(trial.testMessageDomain, false)
				if err != nil {
					t.Fatalf("auth.IssueKey (reader) failed: %v", err)
				}

				decrypted, err := readerKey.DecryptAndVerify(trial.testMessageDomain, msg)
				if err != nil {
					t.Fatalf("DecryptAndVerify failed: %v", err)
				}

				if !slices.Equal(decrypted, plaintext) {
					t.Errorf("Decrypted plaintext mismatch")
				}
			}

			// Test child derivation if the key can derive
			if key2.CanDerive() && trial.testChildDomain != "" {
				child, err := key2.DeriveKey(trial.testChildDomain, false)
				if err != nil {
					t.Fatalf("key2.DeriveKey failed: %v", err)
				}
				if child.DomainName != trial.testChildDomain {
					t.Errorf("Child domain mismatch: got %q, want %q", child.DomainName, trial.testChildDomain)
				}
			}
		})
	}
}

/* ------------------- Benchmarks -------------------  */

func Benchmark_hashLabelToPrime(b *testing.B) {
	label := strings.Repeat("a", MaxLabelLen)
	slotIndex := 0
	for b.Loop() {
		hashLabelToPrime(slotIndex, label)
	}
}

func Benchmark_createSearchTag(b *testing.B) {
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			key, err := auth.IssueKey(trial.domainName, false)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.domainName, err)
			}
			for b.Loop() {
				_, err := createSearchTag(key.Slots)
				if err != nil {
					b.Fatalf("createSearchTag failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkAuthority_IssueKey_reader_nonderivable(b *testing.B) {
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			for b.Loop() {
				_, err := auth.IssueKey(trial.domainName, false)
				if err != nil {
					b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.domainName, err)
				}
			}
		})
	}
}

func BenchmarkAuthority_IssueKey_writer_derivable(b *testing.B) {
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"*"},
		{"*.com"},
		{"*.a.com"},
		{"*.b.a.com"},
		{"*.c.b.a.com"},
		{"*.d.c.b.a.com"},
		{"*.e.d.c.b.a.com"},
		{"*.f.e.d.c.b.a.com"},
		{"*.g.f.e.d.c.b.a.com"},
		{"*.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			for b.Loop() {
				_, err := auth.IssueKey(trial.domainName, true)
				if err != nil {
					b.Fatalf("auth.IssueKey(%q, true) failed: %v", trial.domainName, err)
				}
			}
		})
	}
}

func BenchmarkPrivateKey_DeriveKey_reader_one_wildcard(b *testing.B) {
	auth := NewAuthority(12)
	trials := []struct {
		parentDomainName string
		childDomainName  string
	}{
		{"*", "com"},
		{"*.com", "a.com"},
		{"*.a.com", "b.a.com"},
		{"*.b.a.com", "c.b.a.com"},
		{"*.c.b.a.com", "d.c.b.a.com"},
		{"*.d.c.b.a.com", "e.d.c.b.a.com"},
		{"*.e.d.c.b.a.com", "f.e.d.c.b.a.com"},
		{"*.f.e.d.c.b.a.com", "g.f.e.d.c.b.a.com"},
		{"*.g.f.e.d.c.b.a.com", "h.g.f.e.d.c.b.a.com"},
		{"*.h.g.f.e.d.c.b.a.com", "i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		parentKey, err := auth.IssueKey(trial.parentDomainName, false)
		if err != nil {
			b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.parentDomainName, err)
		}

		b.Run(fmt.Sprintf("parent=%s/child=%s", trial.parentDomainName, trial.childDomainName), func(b *testing.B) {
			for b.Loop() {
				_, err := parentKey.DeriveKey(trial.childDomainName, false)
				if err != nil {
					b.Fatalf("parentKey.DeriveKey(%q, false) failed: %v", trial.childDomainName, err)
				}
			}
		})
	}
}

func BenchmarkPrivateKey_DeriveKey_reader_many_wildcard(b *testing.B) {
	auth := NewAuthority(12)

	parentDomainName := "*.*.*.*.*.*.*.*.*.*"
	parentKey, err := auth.IssueKey(parentDomainName, false)
	if err != nil {
		b.Fatalf("auth.IssueKey(%q, false) failed: %v", parentDomainName, err)
	}

	trials := []struct {
		childDomainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(fmt.Sprintf("parent=%s/child=%s", parentDomainName, trial.childDomainName), func(b *testing.B) {
			for b.Loop() {
				_, err := parentKey.DeriveKey(trial.childDomainName, false)
				if err != nil {
					b.Fatalf("parentKey.DeriveKey(%q, false) failed: %v", trial.childDomainName, err)
				}
			}
		})
	}
}

func Benchmark_encrypt(b *testing.B) {
	auth := NewAuthority(12)
	plaintext := bytesx.Random(1024)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			key, err := auth.IssueKey(trial.domainName, false)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.domainName, err)
			}
			for b.Loop() {
				_, err := encrypt(key, plaintext)
				if err != nil {
					b.Fatalf("encrypt failed: %v", err)
				}
			}
		})
	}
}

func Benchmark_decrypt(b *testing.B) {
	plaintext := bytesx.Random(1024)
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			key, err := auth.IssueKey(trial.domainName, false)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.domainName, err)
			}

			for b.Loop() {
				b.StopTimer()
				// encrypt modifies its input value, thus make a copy
				plain := make([]byte, len(plaintext))
				copy(plain, plaintext)
				message, err := encrypt(key, plain)
				if err != nil {
					b.Fatalf("encrypt failed: %v", err)
				}
				b.StartTimer()
				got, err := decrypt(key, message)

				b.StopTimer()
				if err != nil {
					b.Fatalf("decrypt failed: %v", err)
				}
				if !slices.Equal(plaintext, got) {
					b.Fatalf("decrypted value is different from original")
				}
				b.StartTimer()
			}
		})
	}
}

func Benchmark_sign(b *testing.B) {
	plaintext := bytesx.Random(1024)
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			key, err := auth.IssueKey(trial.domainName, true)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, true) failed: %v", trial.domainName, err)
			}

			for b.Loop() {
				sign(key, plaintext)
			}
		})
	}
}

func Benchmark_verify(b *testing.B) {
	plaintext := bytesx.Random(1024)
	auth := NewAuthority(12)

	trials := []struct {
		domainName string
	}{
		{"com"},
		{"a.com"},
		{"b.a.com"},
		{"c.b.a.com"},
		{"d.c.b.a.com"},
		{"e.d.c.b.a.com"},
		{"f.e.d.c.b.a.com"},
		{"g.f.e.d.c.b.a.com"},
		{"h.g.f.e.d.c.b.a.com"},
		{"i.h.g.f.e.d.c.b.a.com"},
	}

	for _, trial := range trials {
		b.Run(trial.domainName, func(b *testing.B) {
			signingKey, err := auth.IssueKey(trial.domainName, true)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, true) failed: %v", trial.domainName, err)
			}

			verifyingKey, err := auth.IssueKey(trial.domainName, false)
			if err != nil {
				b.Fatalf("auth.IssueKey(%q, false) failed: %v", trial.domainName, err)
			}

			signature := sign(signingKey, plaintext)

			for b.Loop() {
				err := verify(verifyingKey, plaintext, signature)
				if err != nil {
					b.Fatalf("verify failed: %v", err)
				}
			}
		})
	}
}

/*

func BenchmarkPrivateKey_DeriveReader(b *testing.B) {
}

func BenchmarkPrivateKey_EncryptAndSign(b *testing.T) {
}

func BenchmarkPrivateKey_DecryptAndVerify(b *testing.T) {
}

*/
