// Package threshold is the cryptographic core: it cuts a key into M-of-N
// shares, and it reconstructs one — but only after verifying that what it
// reconstructed is the key that was sealed.
//
// # Which Shamir implementation, and why it is not this one
//
// The split and the interpolation come from
// github.com/mvrahden/go-shamir, pinned. They are not hand-rolled here, and
// the full evaluation — eight candidates, with the licence, dependency
// weight, field polynomial, maintenance state and measured secrecy of each —
// is in docs/superpowers/spikes/2026-10-23-shamir-library/NOTES.md. The
// short version, because a reader of this package should not have to go and
// find it:
//
//   - **GF(256) arithmetic is easy to get subtly wrong and impossible to
//     notice getting wrong.** A split with a mistake in it still splits, and
//     still reconstructs, until the day it does not; the failure surfaces as
//     an unrecoverable key rather than as a test failure. So the default is
//     a published implementation that other people's test suites also run
//     against.
//   - The chosen one is MPL-2.0 (compatible with importing from this
//     Apache-2.0 module), cgo-free, stdlib-only, and adds **5 modules** to
//     the build list. The runner-up, github.com/openbao/openbao/sdk/v2,
//     is better maintained but ships those 250 lines inside a monolith that
//     adds **96** — gRPC, the docker client, pgx, OpenTelemetry — which a
//     published library pushes onto every consumer's dependency graph and
//     vulnerability scanner. github.com/hashicorp/vault/shamir is
//     disqualified outright: 545 modules, a BUSL-1.1 module root, and four
//     govulncheck advisories with no fix available that every consumer would
//     inherit.
//   - It is **wire-compatible** with Vault's and OpenBao's, and all three
//     pass the known-answer vector this package tests against, so swapping
//     the dependency is a one-line change the same tests validate. That is
//     what makes the lighter dependency the reversible choice rather than
//     the risky one.
//
// The maintenance risk of a small dependency is converted into tests that
// live here: TestTSSKnownAnswerVector pins the field *and* the share layout
// against draft-mcgrew-tss-03 §9, and TestSharesAreUniformlyDistributed
// measures that k−1 shares still reveal nothing (the measurement that
// disqualified one otherwise-excellent candidate). An upgrade that changed
// either fails this module's CI rather than a consumer's deployment.
//
// # Reconstruction must never return an unverified key
//
// This is the whole reason this package exists rather than being three calls
// at a call site. Shamir's scheme is **not authenticated**, and the
// consequences were measured rather than assumed:
//
//	combine(2 of 5)   err=<nil>  correct=false   // below the threshold
//	corrupted share   err=<nil>  correct=false   // one byte flipped
//
// A wrong key, silently, with no error. A custodian who supplies a corrupted
// or fabricated share does not cause a failure — they cause the ceremony to
// hand back something key-shaped that decrypts to nothing, or worse, that
// gets stored as if it were the key. So every seal records a
// domain.KeyCommitment over the key its generation sealed, and Reconstruct
// compares what it interpolated against that commitment and returns
// domain.ErrReconstructionUnverified **and no key** when they differ.
//
// What that costs is stated on domain.KeyCommitment: secrecy becomes
// computational rather than information-theoretic, because a holder of M−1
// shares can test candidates against the commitment. Over a 32-byte
// uniformly random key that is a 2^256 search. The alternative is returning
// a wrong key with no error, which is not a theoretical failure.
package threshold

import (
	"fmt"

	shamir "github.com/mvrahden/go-shamir"

	"github.com/laenenai/escrow/internal/domain"
)

// Plan is the custody arrangement for one generation of a seal: the
// threshold, who holds the shares, which of them — if any — is the
// deployment itself, and the liveness schedule.
//
// It is the input to both Create and Rotate, and the same type for both on
// purpose: changing custodians is one of the reasons to re-seal, and a
// re-seal that could not express a different arrangement would make charter
// property 4 ("cancelling or changing custodians must make previously
// distributed shares useless") impossible to act on.
type Plan struct {
	// Threshold is the M-of-N. Required, and validated by
	// domain.Threshold.Validate — which is where the floor on M that keeps
	// the deployment insufficient lives.
	Threshold domain.Threshold

	// Holders names the custodians, one per share, exactly Threshold.Total
	// of them, with no duplicates.
	//
	// Its order does not determine the share indices. The splitter chooses
	// the x-coordinates, so Holders[i] is assigned whichever index the i-th
	// cut share turned out to have; the mapping ends up in the seal's
	// Custodians and is the authority thereafter.
	Holders []domain.CustodianID

	// System names the one custodian that is the deployment itself, and must
	// appear in Holders. The zero value means the deployment holds no share
	// at all, which is a stronger arrangement and is permitted — a liveness
	// lapse then has no share to release and the switch is informational.
	//
	// At most one, always: see domain.MaxSystemHeldShares.
	System domain.CustodianID

	// Liveness is the dead-man's-switch schedule. Required, and validated by
	// domain.LivenessSchedule.Validate — which is where the requirement for
	// multiple independent channels and a cancellable grace period lives.
	Liveness domain.LivenessSchedule
}

// Validate reports whether p describes an arrangement this module will cut
// shares for.
func (p Plan) Validate() error {
	if err := p.Threshold.Validate(); err != nil {
		return err
	}
	if len(p.Holders) != p.Threshold.Total {
		return fmt.Errorf("%w: plan names %d holders for a %s threshold: every share has exactly one named holder",
			domain.ErrInvalidArgument, len(p.Holders), p.Threshold)
	}

	seen := make(map[domain.CustodianID]struct{}, len(p.Holders))
	for _, h := range p.Holders {
		if h.IsZero() {
			return fmt.Errorf("%w: plan names an empty holder", domain.ErrInvalidArgument)
		}
		if _, dup := seen[h]; dup {
			return fmt.Errorf("%w: plan names holder %s twice: a threshold counts distinct custodians, so one person holding two shares is one person holding two votes",
				domain.ErrInvalidArgument, h)
		}
		seen[h] = struct{}{}
	}

	if !p.System.IsZero() {
		if _, ok := seen[p.System]; !ok {
			return fmt.Errorf("%w: plan names %s as the deployment's own custodian, but does not list it as a holder",
				domain.ErrInvalidArgument, p.System)
		}
	}
	return p.Liveness.Validate()
}

// PlanFrom returns the plan that reproduces seal's current arrangement. It
// is how a caller rotating a key *without* changing custodians asks for
// that, rather than having to rebuild the holder list by hand and risk
// getting the system custodian wrong.
//
// The holder order follows the seal's custodian slice, which is not
// meaningful — see Plan.Holders — so a round trip through PlanFrom and Rotate
// does not preserve which index belongs to whom. It cannot: a rotation cuts
// new shares at new x-coordinates. What it preserves is *who* holds a share
// and which one of them is the deployment, which is the part that matters.
func PlanFrom(seal domain.Seal) Plan {
	holders := make([]domain.CustodianID, 0, len(seal.Custodians))
	for _, c := range seal.Custodians {
		holders = append(holders, c.ID)
	}
	plan := Plan{
		Threshold: seal.Threshold,
		Holders:   holders,
		Liveness:  seal.Liveness.Clone(),
	}
	if system, ok := seal.SystemCustodian(); ok {
		plan.System = system.ID
	}
	return plan
}

// Create mints a fresh key, cuts it into shares under plan, and returns the
// seal record, the key, and the shares.
//
// The caller owns all three and must handle them accordingly:
//
//   - The **seal** is not secret. Store it (SealStore.CreateSeal).
//   - The **key** is the secret the whole module exists to protect. Use it
//     and then Destroy it. This is the only moment in the key's life when it
//     exists as a single value — after this, it exists only as shares, which
//     is the point.
//   - The **shares** are each secret. Hand each one to its custodian
//     (domain.Share.Export), give the deployment's own to
//     SealStore.HoldShare, and Destroy every copy that remains in the
//     process.
//
// Create deliberately does no I/O and holds nothing. There is no code path
// in this module that stores the key or stores more than one share, because
// there is no code in this module that *has* both after Create returns.
func Create(tenant domain.TenantID, plan Plan, clock domain.Clock) (domain.Seal, domain.SealedKey, []domain.Share, error) {
	if tenant.IsZero() {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("%w: create seal: no tenant", domain.ErrInvalidArgument)
	}
	if err := plan.Validate(); err != nil {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: create seal: %w", err)
	}

	id, err := domain.NewSealID(clock)
	if err != nil {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: create seal: %w", err)
	}
	at := domain.CanonicalTime(clock.Now())

	seal := domain.Seal{
		Tenant:     tenant,
		ID:         id,
		Generation: domain.FirstGeneration,
		Threshold:  plan.Threshold,
		Liveness:   plan.Liveness.Clone(),
		CreatedAt:  at,
		SealedAt:   at,
	}
	return cut(seal, plan)
}

// Rotate mints a *new* key for an existing seal, cuts it into a new
// generation of shares under plan, and returns the rotated seal record, the
// new key and the new shares.
//
// This is CHARTER.md's fourth safety property, and the reason it is a new
// key rather than reissued shares is worth stating plainly: reissuing shares
// over the same key would leave every previously distributed share *still
// able to reconstruct it*. A custodian who had been removed, or who had
// quietly kept a photograph of their share, would still be a custodian. A
// new key makes the old shares useless rather than merely superseded —
// nothing they combine to is the key any more, and no record anywhere says
// it is.
//
// The caller must then re-protect whatever the old key protected under the
// new one, and persist the rotation with SealStore.ReplaceSeal, which
// discards the deployment's old share in the same operation.
//
// It keeps the seal's CreatedAt and advances its Generation by exactly one.
func Rotate(seal domain.Seal, plan Plan, clock domain.Clock) (domain.Seal, domain.SealedKey, []domain.Share, error) {
	if err := seal.Validate(); err != nil {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: rotate seal: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: rotate seal %s: %w", seal.ID, err)
	}

	rotated := domain.Seal{
		Tenant:     seal.Tenant,
		ID:         seal.ID,
		Generation: seal.Generation.Next(),
		Threshold:  plan.Threshold,
		Liveness:   plan.Liveness.Clone(),
		CreatedAt:  seal.CreatedAt,
		SealedAt:   domain.CanonicalTime(clock.Now()),
	}
	return cut(rotated, plan)
}

// cut is the shared tail of Create and Rotate: mint a key, split it, commit
// to it, and attach the custodian assignment. It is one function so that the
// two entry points cannot drift on the order of those four steps — in
// particular so that neither can produce a seal whose commitment was taken
// over a different generation than the shares were cut under.
func cut(seal domain.Seal, plan Plan) (domain.Seal, domain.SealedKey, []domain.Share, error) {
	key, err := domain.NewSealedKey()
	if err != nil {
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: seal %s: %w", seal.ID, err)
	}

	shares, err := split(seal.ID, seal.Generation, plan.Threshold, key)
	if err != nil {
		key.Destroy()
		return domain.Seal{}, domain.SealedKey{}, nil, err
	}

	seal.Commitment = domain.CommitKey(seal.ID, seal.Generation, key)
	seal.Custodians = make([]domain.Custodian, 0, len(shares))
	for i, share := range shares {
		holder := domain.HolderExternal
		if !plan.System.IsZero() && plan.Holders[i] == plan.System {
			holder = domain.HolderSystem
		}
		seal.Custodians = append(seal.Custodians, domain.Custodian{
			ID:     plan.Holders[i],
			Holder: holder,
			Index:  share.Index(),
		})
	}

	// Validated after assembly rather than trusted, because this is the one
	// place a seal is constructed: a seal that failed its own invariants here
	// would be a seal whose shares are already cut, which is exactly the
	// state that must not reach a store.
	if err := seal.Validate(); err != nil {
		destroyAll(shares)
		key.Destroy()
		return domain.Seal{}, domain.SealedKey{}, nil, fmt.Errorf("escrow: seal %s: %w", seal.ID, err)
	}
	return seal, key, shares, nil
}

// split cuts key into th.Total shares of which any th.Required reconstruct
// it, bound to seal and generation.
//
// The library returns each share as len(secret)+1 bytes with the
// x-coordinate in the trailing byte (its ShareOverhead is 1). That layout is
// split apart here, at the one boundary that knows it, so that
// domain.Share's material is exactly domain.KeySize bytes and the index is a
// domain.ShareIndex — and so that an upgrade changing the layout fails in one
// function rather than in every caller. The known-answer test pins the
// layout for exactly that reason.
func split(seal domain.SealID, generation domain.Generation, th domain.Threshold, key domain.SealedKey) ([]domain.Share, error) {
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("escrow: split key for seal %s: %w", seal, err)
	}
	if err := th.Validate(); err != nil {
		return nil, err
	}

	parts, err := shamir.Split(key.Bytes(), th.Total, th.Required)
	if err != nil {
		// The library's errors name counts and never material — verified in
		// the spike — but this is the one place that is true by inspection
		// rather than by construction, so the error is wrapped behind a
		// sentinel and the seal is named instead of the key.
		return nil, fmt.Errorf("escrow: split key for seal %s into %s: %w: %w",
			seal, th, domain.ErrInvalidKeyMaterial, err)
	}
	if len(parts) != th.Total {
		return nil, fmt.Errorf("escrow: split key for seal %s into %s: %w: the splitter returned %d shares",
			seal, th, domain.ErrInvalidShare, len(parts))
	}

	shares := make([]domain.Share, 0, len(parts))
	for _, part := range parts {
		if len(part) != domain.KeySize+shamir.ShareOverhead {
			destroyAll(shares)
			return nil, fmt.Errorf("escrow: split key for seal %s: %w: the splitter returned a %d-byte share",
				seal, domain.ErrInvalidShare, len(part))
		}
		material, index := part[:domain.KeySize], domain.ShareIndex(part[domain.KeySize])
		share, err := domain.NewShare(seal, generation, index, material)
		// The library's buffer is zeroized whether or not the share was
		// accepted: NewShare copies, so this one is now a redundant copy of
		// a secret, and a redundant copy of a secret is a leak waiting for a
		// heap dump.
		clear(part)
		if err != nil {
			destroyAll(shares)
			return nil, fmt.Errorf("escrow: split key for seal %s: %w", seal, err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

// Reconstruct interpolates the key of seal's current generation from shares
// and returns it **only if** it matches the seal's commitment.
//
// The checks happen in this order, and the order is the contract:
//
//  1. The seal must be a valid seal record.
//  2. Every share must belong to this seal and this generation, or
//     domain.ErrForeignShare. Cheap, and it is how a share from a
//     superseded generation is refused before any arithmetic.
//  3. No two shares may carry the same index, or domain.ErrDuplicateShare.
//     Interpolating over a repeated point has no more information than over
//     one of them, so accepting duplicates would let one custodian satisfy
//     an M-of-N threshold by presenting one share M times.
//  4. There must be at least Threshold.Required of them, or
//     domain.ErrInsufficientShares. This is checked *before* interpolating
//     because the library does not refuse a below-threshold set — it
//     interpolates whatever it was given and returns a wrong key with a nil
//     error.
//  5. The interpolated value must match the commitment, or
//     domain.ErrReconstructionUnverified **and no key**.
//
// # Every presented share is used, and no subset is searched
//
// If the set fails its commitment, Reconstruct does not try the C(n,k)
// subsets to find one that works. It could — that is a few thousand
// interpolations for a realistic seal — and it deliberately does not, for
// two reasons. A search that succeeded would identify the bad share by
// elimination, which is an accusation against a named person produced by an
// algorithm that cannot tell malice from a photocopier; and a search that
// failed would have spent the ceremony's time proving a negative. Who
// supplied a share that was not a share is a human judgement made with the
// attempt trail in hand, which is what the trail is for.
//
// # The error names nothing
//
// domain.ErrReconstructionUnverified carries the seal and the generation and
// no more: not the candidate key, not its length, not which share was
// suspected, not how many bytes of the commitment matched. The candidate is
// zeroized before the error is returned.
func Reconstruct(seal domain.Seal, shares []domain.Share) (domain.SealedKey, error) {
	if err := seal.Validate(); err != nil {
		return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct: %w", err)
	}

	parts := make([][]byte, 0, len(shares))
	seen := make(map[domain.ShareIndex]struct{}, len(shares))
	for _, share := range shares {
		if err := share.Validate(); err != nil {
			return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s: %w", seal.ID, err)
		}
		if share.Seal() != seal.ID {
			return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s: %w: a presented share is of seal %s",
				seal.ID, domain.ErrForeignShare, share.Seal())
		}
		if share.Generation() != seal.Generation {
			return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s %s: %w: a presented share is %s",
				seal.ID, seal.Generation, domain.ErrForeignShare, share.Generation())
		}
		if _, dup := seen[share.Index()]; dup {
			return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s: %w: share index %d was presented twice",
				seal.ID, domain.ErrDuplicateShare, share.Index())
		}
		seen[share.Index()] = struct{}{}

		part := make([]byte, 0, domain.KeySize+shamir.ShareOverhead)
		part = append(part, share.Material()...)
		part = append(part, byte(share.Index()))
		parts = append(parts, part)
	}
	// The assembled parts are copies of share material and are zeroized
	// however this function returns.
	defer func() {
		for _, part := range parts {
			clear(part)
		}
	}()

	if len(parts) < seal.Threshold.Required {
		return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s: %w: %d distinct shares presented, %s requires %d",
			seal.ID, domain.ErrInsufficientShares, len(parts), seal.Threshold, seal.Threshold.Required)
	}

	raw, err := shamir.Combine(parts)
	// Zeroized on every path: it is the key, or it is a wrong value derived
	// from real share material, and neither belongs in a buffer nobody owns.
	// (A closure rather than `defer clear(raw)`, which Go does not permit:
	// clear is one of the built-ins that may not appear in a defer.)
	defer func() { clear(raw) }()
	if err != nil {
		// Reached only if the library rejects the set outright — a duplicate
		// index it caught that the check above somehow did not, or a length
		// mismatch. Reported as unverified rather than as a storage or
		// argument error, because from the caller's point of view the
		// outcome is identical: no key, and the set is not trustworthy.
		return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s %s: %w",
			seal.ID, seal.Generation, domain.ErrReconstructionUnverified)
	}

	candidate, err := domain.SealedKeyFrom(raw)
	if err != nil {
		// A wrong length or an all-zero interpolation is a failed
		// reconstruction, not bad input: the input was shares, and they
		// validated. Mapping it onto ErrInvalidKeyMaterial would tell the
		// caller to fix its arguments when what it should do is distrust the
		// set.
		return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s %s: %w",
			seal.ID, seal.Generation, domain.ErrReconstructionUnverified)
	}

	if !seal.Commitment.Equal(domain.CommitKey(seal.ID, seal.Generation, candidate)) {
		candidate.Destroy()
		return domain.SealedKey{}, fmt.Errorf("escrow: reconstruct seal %s %s: %w: the key the presented shares interpolate to is not the key this generation sealed",
			seal.ID, seal.Generation, domain.ErrReconstructionUnverified)
	}
	return candidate, nil
}

// destroyAll zeroizes every share in s. It is the cleanup path for a split
// that failed partway: shares already cut are real share material, and
// abandoning them unzeroized would leave the secret in a buffer no caller
// knows about.
func destroyAll(s []domain.Share) {
	for i := range s {
		s[i].Destroy()
	}
}
