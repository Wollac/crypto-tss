package sss_test

import (
	"testing"

	"github.com/iotaledger/crypto-tss/demo/pkg/sss"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

const (
	N = 5
	T = N/2 + 1
)

var suite = suites.MustFind("Ed25519")

func TestGenerateSecretShares(t *testing.T) {
	keyShares := sss.GenerateSecretShares(suite, suite.Scalar().One(), T, N)
	require.Len(t, keyShares, N)

	var priShares []*share.PriShare
	for _, keyShare := range keyShares {
		require.Len(t, keyShare.Commitments(), T)
		priShares = append(priShares, keyShare.PriShare())
	}

	secret, err := share.RecoverSecret(suite, priShares[:T], T, N)
	require.NoError(t, err)
	require.Equal(t, suite.Scalar().One(), secret)
}

func TestUnmarshalSecretShare(t *testing.T) {
	keyShares := sss.GenerateSecretShares(suite, suite.Scalar().One(), T, N)

	keyShare := keyShares[0]
	data, err := keyShare.MarshalBinary()
	require.NoError(t, err)

	parsed, err := sss.UnmarshalSecretShare(suite, data)
	require.NoError(t, err)

	require.Equal(t, keyShare.PriShare(), parsed.PriShare())
	require.Len(t, parsed.Commitments(), len(keyShare.Commitments()))
	for i, commit := range keyShare.Commitments() {
		require.True(t, commit.Equal(parsed.Commitments()[i]))
	}
}
