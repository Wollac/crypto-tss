package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/iotaledger/crypto-tss/demo/pkg/sss"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/dss"
	"go.dedis.ch/kyber/v3/suites"
)

// command-line flags
var (
	Shares  bytesSlice
	Message = flag.String("message", "Hello World!", "message to sign")
)

const suiteName = "Ed25519"

func main() {
	flag.Var(&Shares, "s", "nonce share")
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

// Peer contains the cryptographic fields of a peer.
type Peer struct {
	private kyber.Scalar
	public  kyber.Point

	long dss.DistKeyShare // longterm distributed key
}

// Peers represents a slice of Peer
type Peers []Peer

// Public returns the public keys of each peer.
func (p Peers) Public() (pubs []kyber.Point) {
	for _, peer := range p {
		pubs = append(pubs, peer.public)
	}
	return pubs
}

func run() error {
	suite, err := suites.Find(suiteName)
	if err != nil {
		return fmt.Errorf("failed to load suite '%s': %w", suiteName, err)
	}
	if len(Shares) == 0 {
		return fmt.Errorf("no nonce shares provided")
	}

	// decode nonces provided as flags
	nonces, err := ParseFlags(suite)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	// derive t and n from the provided nonces
	t, n := GetParameters(nonces)

	fmt.Printf("==> (%d,%d)-threshold scheme\n", t, n)
	for _, nonce := range nonces {
		fmt.Printf(" share %d (t=%d): %s\n", nonce.PriShare().I, nonce.Threshold(), nonce.PriShare().V)
	}

	// 1) create n dummy peers
	peers := GenerateKeyPairs(suite, n)

	// 2) compute distributed key
	publicKeyKyber := RunDKG(suite, peers, t)

	// message to sign
	msg := []byte(*Message)

	var signers []*dss.DSS
	for i := range nonces {
		signer, err := NewSigner(suite, peers[i], peers.Public(), nonces[i], msg, t)
		if err != nil {
			return fmt.Errorf("failed to create signer: %w", err)
		}
		signers = append(signers, signer)
	}

	// make the first signer the signature aggregator
	aggregator := signers[0]

	// 3) create and aggregate partial signatures until the threshold T is reached
	for _, signer := range signers {
		sig, err := signer.PartialSig()
		if err != nil {
			return fmt.Errorf("failed to create partial signature: %w", err)
		}
		// the aggregator does not need to process its own signature, but PartialSig still needs to be called
		if signer == aggregator {
			continue
		}

		if err := aggregator.ProcessPartialSig(sig); err != nil {
			return fmt.Errorf("invalid partial signature: %w", err)
		}
		// we can stop as soon as the threshold is reached
		if aggregator.EnoughPartialSig() {
			break
		}
	}

	// 4) produce the aggregated complete signature
	sig, err := signers[0].Signature()
	if err != nil {
		return fmt.Errorf("failed to aggregate signature: %w", err)
	}

	// the marshaled Point corresponds to the RFC 8032 compatible public key
	publicKey, _ := publicKeyKyber.MarshalBinary()

	// check that the signature validates against stdlib
	if !ed25519.Verify(publicKey, msg, sig) {
		panic("invalid signature generated")
	}

	fmt.Printf("\n==> Ed25519 signature from %d signers\n", aggregator.T)
	fmt.Printf(" public key (%d-byte):\t%x\n", len(publicKey), publicKey)
	fmt.Printf(" message (%d-byte):\t%s\n", len(*Message), *Message)
	fmt.Printf(" signature (%d-byte):\t%x\n", len(sig), sig)

	return nil
}

// GenerateKeyPairs generates a key-pair for each peer.
func GenerateKeyPairs(suite suites.Suite, n int) Peers {
	peers := make([]Peer, n)
	for i := range peers {
		priv := suite.Scalar().Pick(suite.RandomStream())
		peers[i] = Peer{private: priv, public: suite.Point().Mul(priv, nil)}
	}
	return peers
}

// RunDKG generates the longterm distributed key.
// It returns the public key and sets the private key shares in each peer.
func RunDKG(suite suites.Suite, peers Peers, t int) kyber.Point {
	// TODO: Run an actual DKG instead of dealer based SSS
	shares := sss.GenerateSecretShares(suite, nil, t, len(peers))
	for i := range peers {
		peers[i].long = shares[i]
	}
	return shares[0].Public()
}

// NewSigner creates a new signer
func NewSigner(suite suites.Suite, peer Peer, PublicKeys []kyber.Point, nonce dss.DistKeyShare, msg []byte, T int) (*dss.DSS, error) {
	return dss.NewDSS(suite, peer.private, PublicKeys, peer.long, nonce, msg, T)
}

// utilities to handle the flags correctly

// ParseFlags decodes and returns the secret shares passed as command-line flags.
func ParseFlags(suite suites.Suite) (map[int]*sss.SecretShare, error) {
	shares := map[int]*sss.SecretShare{}
	for i, share := range Shares {
		ss, err := sss.UnmarshalSecretShare(suite, share)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share %d: %w", i, err)
		}
		shares[ss.PriShare().I] = ss
	}
	return shares, nil
}

// GetParameters derives the scheme parameters from the provided nonces.
func GetParameters(nonces map[int]*sss.SecretShare) (int, int) {
	max := -1
	for i := range nonces {
		if i > max {
			max = i
		}
	}
	return len(nonces[max].Commitments()), max + 1
}

// base64 encoded byte slice
type bytes []byte

func (b bytes) String() string { return base64.StdEncoding.EncodeToString(b) }

func (b *bytes) Set(s string) (err error) {
	*b, err = base64.StdEncoding.DecodeString(s)
	return err
}

// slice of base64 encoded bytes
type bytesSlice []bytes

func (b bytesSlice) String() string { return fmt.Sprintf("%v", []bytes(b)) }

func (b *bytesSlice) Set(s string) error {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = append(*b, buf)
	return nil
}
