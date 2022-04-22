# Monorepo for Threshold Ed25519

## Repository

- [demo](https://github.com/iotaledger/crypto-tss/tree/main/demo): Golang demos and PoCs
- [talks](https://github.com/iotaledger/crypto-tss/tree/main/talks): Internal talks and presentations

## Background

In the following section we describe the general ideas behind threshold Ed25519 and potential deployment steps.

In general, there are two key alternatives:
1. Run DKG only for the key (during setup)
2. Run DKG for the key (during setup) and the nonce (for every signing)

### Frost

For the first option there is a vetted 3-round (less with precomputation) scheme with security proofs: Frost [[KG20](https://eprint.iacr.org/2020/852)], [Coinbase blog post](https://blog.coinbase.com/frost-flexible-round-optimized-schnorr-threshold-signatures-b2e950164ee1)  (Rust:[dalek](https://github.com/isislovecruft/frost-dalek), Go:[Coinbase](https://github.com/coinbase/kryptology), [Taurus](https://github.com/taurusgroup/frost-ed25519)).
In order to remove the dependency on a second DKG, the subset of signers needs to be fixed before signing. This makes it very well suited for "human threshold schemes" where usually the actual signers come together anyways, but less for automated signing where signers could go offline. There exists a trivial algorithm to cope with this, but it requires 𝓞(f) rounds, where f is the number of malicious parties.

#### Pros
- Low round complexity
- Works for dishonest majority, i.e. t > n/2
- Provable secure against concurrent sessions
- Very well understood and analyzed in theory and code
- Based on simple cryptographic building blocks

#### Cons
- Conceptually rather different than threshold BLS
- Rounds are cumbersome in asynchronous model and precomputations make it sate-full
- Fixing the subset of singers of signing can be difficult

### Distributed Schnorr Signatures (DSS)

The second option can be achieved using DSS [[SS01](https://www.researchgate.net/profile/Willy-Susilo/publication/242499559_Information_Security_and_Privacy_13th_Australasian_Conference_ACISP_2008_Wollongong_Australia_July_7-9_2008_Proceedings/links/00b495314f3bcaaa46000000/Information-Security-and-Privacy-13th-Australasian-Conference-ACISP-2008-Wollongong-Australia-July-7-9-2008-Proceedings.pdf#page=426)] (Go:[Coinbase](https://github.com/coinbase/kryptology), [Kyber](https://github.com/dedis/kyber)).
Every signer creates a partial signature that can then be aggregated in one round. It however depends on a previous iteration of a DKG to compute a secure nonce.

#### Pros
- Conceptually identical to threshold BLS
- Very simple (complexity lies in the DKG)
- Any DKG can be used, which makes it very flexible for all different use-cases and scenarios (a-/synchronous, with/wo precomputation, robustness, low bandwith/low latency)
- Should be secure against concurrent session (TODO: verify/prove this)
- The subset of signers does not need to be fixed; aggregated signature can be created as soon as at least t signatures have been collected

#### Cons
- Requires DKG execution for every sign
- Security properties mostly depend on the DKG
- Especially due to the vast number of DKG-options, complete solution is not very good analyzed/vetted

#### Implementation Stages

In the following we present implementation ideas and changes for secure threshold Signatures using DSS in an asynchronous network model.

##### 1) Use precomputed nonce

- Run SSS offline on trusted machine, do derive n share of a single secret (nonce)
- Add the corresponding share to the initial config for every party
- During setup run any DKG (preferably probably FROST-DKG) to derive the shared public key. This leads to a synchronous, non-robust setup phase, which is acceptable. (Alternatively, one could also run a dealer-based SSS for this exactly as for the nonce.)
- Every party creates a partial signature using the pre-configured share. No additional interaction needed: one round
- Aggregate t signatures

> **:fire: Warning**
> This scheme is insecure and *must* not be used in practice: Signing two messages with the same nonce reveals the private key!

Examples for share generation and signing using [Kyber](https://github.com/dedis/kyber) can be found under [demo](https://github.com/iotaledger/crypto-tss/tree/main/demo).

###### Pros

- Exactly the same process as Threshold BLS using Kyber - minimal code changes required
- No additional network requirements
- Deterministic signatures
- Very fast (no communication during DKG)

###### Cons

- Not trustless
- Only secure as OTS; potentially acceptable for tests and devnet

##### 2) Use precomputed nonce-list

- Same as 1), but generate shares for multiple nonces.
- Every party creates a partial signature with index i
- Increment the state i for all parties
- Aggregate t signatures

###### Pros

- Very similar to threshold BLS using Kyber
- No additional network requirements
- Very fast (no communication during DKG)

###### Cons

- Not trustless
- Stateful, e.g. state also needs to be incremented on offline nodes
- Numbers of signs limited

##### 3) Honest nonce-DKG

- During setup run any DKG (preferably probably FROST-DKG) to derive the shared public key. This leads to a synchronous, non-robust setup phase.
- As part of the signing process, for every party:
  - Sample secret s = a₀
  - C = (A₀,A₁,…,Aₜ),(y₁,y₂,…,yₙ) ← <span style="font-variant:small-caps;">VSS</span>(s)
  - Broadcast C and send yᵢ to party i
  - Receive and FeldmanVerify deals with Δ-timeout
  - Exclude invalid deals or missing deals from key share computation
  - Fail if |deals| ≤ f
  - Create partial signatures using the key share
  - (Nonce generation can be decoupled and run in advanced for immediate one-round singing)
- Aggregate t signatures

###### Pros

- Unlimited stateless signing
- Nonce generation easy to implement with Kyber primitives
- Partial signatures and aggregation similar to threshold BLS using Kyber
- Trustless
- Very fast (one round DKG)

###### Cons

- Only works in a strong synchronous setting without malicious (but with offline) actors in DKG; maybe acceptable testing and experiments
- Nonce generation simple but specific to that approach
- Probably unnecessary step, compared to 2) and 4)

##### 4) Asynchronous nonce-DKG

###### Variant a)

- Setup
  - Run any DKG (preferably probably FROST-DKG) to derive the aggregated public key and private key share. This leads to a synchronous, non-robust setup phase.
- Nonce sharing (can be started any time before the signing process)
  - For every party i:
    - Sample secret s = a₀
    - Run ACSSᵢ(s):
      - C=(A₀,A₁,…,Aₜ), e=(Enc<sub>pk₀</sub>(y₀),…,Enc<sub>pkₙ</sub>(yₙ)) ← <span style="font-variant:small-caps;">VSSEncAndProve</span>(s)
      - Broadcast (C,e) using Verified Reliable Broadcast (RBC) with predicate: C is valid
    - On termination of ACSSⱼ:
      - sʲᵢ ← output
      - Tᵢ ← Tᵢ ∪ {j}
    - Wait until |Tᵢ| ≥ n - f 
- Signing process
  - For every party i:
    - Input Tᵢ (bit vector) into Verified ACS with predicate: |Tᵢ| ≥ n - f
    - On termination of ACS:
      - 𝒯 ← {j | the j-th bit is set in at least f+1 elements of the output}<br> (One can show that |𝒯| ≥ f + 1 will always hold. Thus, one honest dealer will always be included.)
      - Wait until 𝒯 ⊆ Tᵢ<br> (as for each j in 𝒯 at least one honest peer observed a termination of ACSSⱼ, this will eventually succeed.) 
      - σᵢ ← sum(sʲᵢ for j in 𝒯)
    - Create partial signature using the private key share and σᵢ as the nonce share
  - Aggregate t partial signatures to form the valid signature

###### Variant b)

- During setup run any DKG (preferably probably FROST-DKG) to derive the shared public key. This leads to a synchronous, non-robust setup phase.
- Nonce DKG (run before each signing)
  - For every party _i_:
    - Sample secret s = a₀
    - Run ACSSᵢ(s):
      - C=(A₀,A₁,…,Aₜ), e=(Enc<sub>pk₀</sub>(y₀),…,Enc<sub>pkₙ</sub>(yₙ)) ← <span style="font-variant:small-caps;">VSSEncAndProve</span>(s)
      - Broadcast (C,e) using Verified Reliable Broadcast (RBC) with predicate: C is valid
    - On termination of ACSSⱼ:
      - sʲᵢ ← output
      - Tᵢ ← Tᵢ ∪ {j}
      - If |Tᵢ| = f+1: RBCᵢ(Tᵢ)
    - Only participate in RPCⱼ when Tⱼ ⊆ Tᵢ
    - On termination of RPCⱼ:
      - 𝒯ᵢ ← 𝒯ᵢ ∪ {j}
- Signing process
  - For every party _i_:
    - Include 𝒯ᵢ (bit vector) into Asynchronous Common Subset (ACS) input
    - On termination of ACS:
      - ℐ ← \{j | j-th bit is set in at least f+1 elements of the output\}<br> ℐ could be empty, in that case the signing needs to be restarted.
      - 𝒯 ← union(Tⱼ for j in ℐ)
      - σᵢ ← sum(sʲᵢ for j in 𝒯)
    - Create partial signatures using the key share and σᵢ as the nonce share
- Aggregate t signatures

###### Pros

- Trustless, stateless and asynchronous
- Partial signatures and aggregation similar to threshold BLS using Kyber
- Nonce key generation can be run independently of the signing, or even in a nonce-pool

###### Cons

- Security of the scheme depends on the used VSS:
  - Feldman VSS is secure up to Berserck attackers
  - PVSS provide full security
- Nonce generation requires two additional RBC rounds

##### 5) Integrate consensus into nonce-DKG

Number of rounds and communication overhead can be reduced by integrating nonce-DKG into consensus (ACS)
