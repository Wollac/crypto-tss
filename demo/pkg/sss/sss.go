package sss

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

// GenerateSecretShares creates N new shares of secret with threshold t.
// If secret is nil, a new secret is chosen randomly.
func GenerateSecretShares(suite suites.Suite, secret kyber.Scalar, t int, n int) []*SecretShare {
	poly := share.NewPriPoly(suite, t, secret, suite.RandomStream())
	_, commits := poly.Commit(suite.Point().Base()).Info()
	priShares := poly.Shares(n)

	keyShares := make([]*SecretShare, n)
	for i, priShare := range priShares {
		keyShares[i] = &SecretShare{commits: commits, share: priShare}
	}
	return keyShares
}
