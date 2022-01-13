package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/iotaledger/crypto-tss/demo/pkg/sss"
	"go.dedis.ch/kyber/v3/suites"
)

// command-line flags
var (
	T     = flag.Int("t", 2, "threshold t of the (t,n)-threshold scheme")
	N     = flag.Int("n", 3, "number of players n of the (t,n)-threshold scheme")
	Count = flag.Int("count", 1, "number of secrets to generate")
)

const (
	suiteName    = "Ed25519"
	jsonFileName = "shares.json"
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	suite, err := suites.Find(suiteName)
	if err != nil {
		return fmt.Errorf("failed to load suite '%s': %w", suiteName, err)
	}

	fmt.Printf("==> Generate %d shared secrets in a (%d,%d)-threshold scheme\n", *Count, *T, *N)

	jsonMap := map[string][][]byte{}
	for i := 0; i < *Count; i++ {
		secret := suite.Scalar().Pick(suite.RandomStream())
		shares := sss.GenerateSecretShares(suite, secret, *T, *N)

		fmt.Printf("  secret %d: %s\n", i, secret.String())
		for _, share := range shares {
			b, err := share.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal key share: %w", err)
			}
			fmt.Printf("    share %02d (%d-byte): %s\n", share.PriShare().I, len(b), base64.StdEncoding.EncodeToString(b))

			key := fmt.Sprintf("player %d", share.PriShare().I)
			jsonMap[key] = append(jsonMap[key], b)
		}
	}

	file, err := os.Create(jsonFileName)
	defer file.Close()
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(jsonMap); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	fmt.Printf("\n==> Stored %d shares in '%s'\n", len(jsonMap)**Count, file.Name())
	return nil
}
