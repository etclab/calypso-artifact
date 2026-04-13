package calypso_test

import (
	"fmt"
	"log"

	"github.com/etclab/calypso"
)

func Example() {
	auth := calypso.NewAuthority(10)

	writerKey, err := auth.IssueKey("*.a.com", true)
	if err != nil {
		log.Fatalf("IssueKey failed for writer \"*.a.com\": %v", err)
	}

	readerKey, err := auth.IssueKey("www.a.com", false)
	if err != nil {
		log.Fatalf("IssueKey failed for reader \"www.a.com\": %v", err)
	}

	plaintext := "The quick brown fox jumps over the lazy dog."
	msg, err := writerKey.EncryptAndSign("www.a.com", []byte(plaintext))
	if err != nil {
		log.Fatalf("EncryptAndSign failed: %v", err)
	}
	log.Println("message's search tag:", msg.SearchTag)
	log.Println(" reader's search tag:", readerKey.SearchTag)

	got, err := readerKey.DecryptAndVerify("www.a.com", msg)
	if err != nil {
		log.Fatalf("DecryptAndVerify failed: %v", err)
	}

	fmt.Println(string(got))
	// Output:
	// The quick brown fox jumps over the lazy dog.
}
