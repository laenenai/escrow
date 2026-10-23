// Package domain is the single home for every value object in the escrow
// module: the seal and its custodians (this file), the secret material a
// seal protects and the shares it is split into (secret.go), the
// identifiers (ids.go), the liveness state machine (liveness.go), the
// release conditions, ceremony records and attempt-trail events
// (release.go), the clock (clock.go) and the error taxonomy (errors.go).
//
// Nothing here performs I/O, reads a clock on its own, starts a goroutine,
// or decides what the sealed thing is. The root package escrow re-exports
// what a consumer needs to name as type aliases, so this package stays the
// only one that defines them.
//
// # The invariants this package holds
//
// CHARTER.md states five safety properties and says they are the whole
// module. Four of them are enforced here, in the types, rather than in the
// code paths that use them — because a code path that has to remember an
// invariant will eventually forget:
//
//  1. **The system holds at most one share and is never sufficient.**
//     Threshold.Validate refuses a required count below MinThreshold, and
//     Seal.Validate refuses more than MaxSystemHeldShares custodians of kind
//     HolderSystem and refuses any seal whose system-held count reaches its
//     required count. Together those mean the deployment's share set is
//     strictly smaller than the threshold for every seal the API will
//     accept. The storage half — that a store cannot physically hold two —
//     is ErrShareAlreadyHeld and the stores' single-row-per-seal shape.
//  2. **A liveness lapse releases a share, not the content.** The effect of
//     a satisfied release condition is a function of its kind
//     (ReleaseConditionKind.Effect in release.go), and the lapse's effect is
//     EffectShareRelease. There is no code path from Evaluate to a key.
//  3. **Escalating notification, then a cancellable grace period.**
//     LivenessSchedule.Validate refuses a schedule with fewer than
//     MinEscalationChannels independent channels or a non-positive grace
//     period, and Evaluate derives the whole state from the most recent
//     proof of life, so a single proof moves every subsequent instant.
//  4. **Re-seal rotates the key.** A Share carries the Generation it was cut
//     under, and a seal's Commitment is over its own generation's key, so a
//     share from a superseded generation fails — by inspection first
//     (ErrForeignShare) and by the commitment if its binding was rewritten
//     (ErrReconstructionUnverified).
//
// The fifth — that the ceremony must be executable by someone who cannot ask
// the author — is documentation, and is not yet delivered. See README.md's
// status section.
//
// # No secret in any error
//
// No error constructed in this package reproduces key material or share
// bytes, or any encoding or the length of either. Errors name the seal, the
// generation and the share index. See errors.go and secret.go.
package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

// keyCommitmentTag is the domain-separation string mixed into every key
// commitment. Without it, a SHA-256 digest this module computed over some
// other protocol's bytes could be mistaken for a commitment, and vice versa.
//
// It carries no organisation or module path. audit recorded why: a
// module-path correction rewrote its entry tag by textual substitution, and
// a cryptographic constant that a repository rename can edit is a
// cryptographic constant waiting to be edited. TestKeyCommitmentTagIsPinned
// asserts this literal, so the next change to it reports itself by name
// rather than as a seal whose shares stop verifying.
//
// It changes only together with commitmentVersion, and either change
// invalidates every stored commitment — see CommitKey.
const keyCommitmentTag = "escrow:key-commitment:v1"

// commitmentVersion is the leading byte of every committed preimage, so that
// a future format change is detectable in the bytes rather than inferred
// from a commitment that no longer matches.
const commitmentVersion byte = 0x01

// MinThreshold is the smallest required share count this module will accept:
// 2.
//
// This is charter property 1 expressed as a number, and it is the reason it
// is a constant rather than a validation rule somebody could relax. The
// system holds at most MaxSystemHeldShares shares; a 1-of-N seal would
// therefore be a seal the deployment can open on its own, which is the one
// thing the module exists to make impossible. A caller that wants a key the
// system can use does not want this module — it wants keyring.
const MinThreshold = 2

// MaxShares is the largest total share count: 255.
//
// It is the field's limit rather than a policy. Shamir's scheme over GF(256)
// evaluates the polynomial at x = 1..255; x = 0 is the secret itself, and
// there is no 256th distinct point. A seal asking for more shares than
// distinct points exist is not a seal with a generous custodian list, it is
// a seal that cannot be cut, so it is refused at validation rather than
// discovered at split time.
const MaxShares = 255

// MaxSystemHeldShares is how many shares the deployment may hold for one
// seal: 1.
//
// One rather than zero, deliberately, and CHARTER.md says why it cuts both
// ways: a system that holds no share cannot contribute to a release at all,
// and a system that holds two is two steps closer to being able to unseal
// alone. One share means the deployment is neither necessary nor sufficient,
// which is the only arrangement that is wrong in neither direction.
const MaxSystemHeldShares = 1

// Generation is which sealing of a seal a key, a commitment and a share
// belong to. Generation FirstGeneration is the seal as first created, and
// every re-seal mints a new key and advances it.
//
// It is the field that makes charter property 4 checkable rather than
// asserted. Cancelling a seal or changing its custodians must make
// previously distributed shares *useless*, not merely superseded, so a
// re-seal is a new key — and a share carries the generation it was cut
// under, so a share from an earlier one is rejected before any arithmetic
// happens.
//
// Numbering starts at one so that the zero value of a Share, or a column
// that was never populated, is detectably invalid rather than silently
// meaning "the first sealing".
type Generation uint32

// FirstGeneration is the generation a seal has when it is created.
const FirstGeneration Generation = 1

// Validate reports whether g names a real generation, i.e. is not zero.
func (g Generation) Validate() error {
	if g < FirstGeneration {
		return invalidf(ErrInvalidArgument, "generation %d: numbering starts at %d", uint32(g), uint32(FirstGeneration))
	}
	return nil
}

// Next returns the generation that follows g.
func (g Generation) Next() Generation { return g + 1 }

// String renders the generation as "g3", the form that appears in logs,
// ceremony records and audit entries.
func (g Generation) String() string { return "g" + strconv.FormatUint(uint64(g), 10) }

// Threshold is a seal's M-of-N: how many distinct shares must be presented
// to reconstruct the key, and how many were cut.
//
// Both halves are counts rather than a ratio, because a ratio would have to
// be rounded and the rounding of a threshold is not a detail: 2-of-3 and
// 3-of-3 are different custody arrangements with different failure modes,
// and "two thirds" names neither.
type Threshold struct {
	// Required is M: how many distinct shares reconstruct the key. At least
	// MinThreshold — see that constant for why the lower bound is a safety
	// property rather than a convenience.
	Required int
	// Total is N: how many shares were cut. At least Required, at most
	// MaxShares.
	Total int
}

// Validate reports whether t is a threshold this module will accept, as a
// wrapped ErrInvalidThreshold.
//
// The lower bound on Required is the interesting one: it is charter property
// 1, and a caller that catches ErrInvalidThreshold is catching an attempt to
// create a seal the deployment could open on its own.
func (t Threshold) Validate() error {
	switch {
	case t.Required < MinThreshold:
		return invalidf(ErrInvalidThreshold, "%d of %d: at least %d shares must be required, or the deployment's own share could be sufficient",
			t.Required, t.Total, MinThreshold)
	case t.Total < t.Required:
		return invalidf(ErrInvalidThreshold, "%d of %d: fewer shares exist than are required, so the key could never be reconstructed",
			t.Required, t.Total)
	case t.Total > MaxShares:
		return invalidf(ErrInvalidThreshold, "%d of %d: at most %d shares can be cut", t.Required, t.Total, MaxShares)
	}
	return nil
}

// String renders the threshold as "2-of-3".
func (t Threshold) String() string {
	return strconv.Itoa(t.Required) + "-of-" + strconv.Itoa(t.Total)
}

// KeyCommitment is a tagged SHA-256 digest binding a seal and generation to
// the exact key that generation sealed. It is what makes reconstruction
// verified rather than hopeful.
//
// It is a fixed-size array rather than a []byte so that it is comparable
// with ==, usable as a map key, and impossible to hand around as a nil or
// wrong-length slice. The zero KeyCommitment is reserved and means "no
// commitment", which Seal.Validate rejects: a seal with no commitment is a
// seal whose reconstruction cannot be verified, and that is the one state
// this module must never store.
//
// A commitment is not a secret and is stored beside the seal. What it costs
// is stated here rather than discovered later: **it trades Shamir's
// information-theoretic secrecy for computational secrecy.** Without it, M−1
// shares reveal exactly nothing about the key, as a theorem. With it, a
// holder of M−1 shares can test a candidate key against the commitment, so
// the key is protected by the infeasibility of searching 2^256 uniformly
// random keys rather than by information theory. That is an enormous margin
// and the right trade — the alternative is returning a wrong key with no
// error, which is not a theoretical failure — but it is a real reduction and
// it belongs in the record. SLIP-0039 makes the same trade for the same
// reason.
type KeyCommitment [sha256.Size]byte

// CommitKey returns the commitment for key as the key of seal's given
// generation. It is
//
//	SHA-256( len(tag) || tag || version || len(seal) || seal || generation || len(key) || key )
//
// where len is an 8-byte big-endian length, tag is keyCommitmentTag, version
// is commitmentVersion, and generation is 4 bytes big-endian. The tag and its
// length come first so that the digest cannot be confused with a digest over
// any other protocol's bytes — the same construction audit uses for its entry
// digest, and for the same reason.
//
// The seal id and generation are inside the digest, not merely stored next to
// it. Without them a commitment could be lifted from one seal's record and
// pasted into another's, and a key that verified under the first would verify
// under the second; with them, a commitment is a statement about one key of
// one generation of one seal and about nothing else. That is what makes a
// share from a different seal fail even when its binding has been rewritten
// to claim this one.
//
// Changing this construction invalidates every commitment ever stored, which
// would make every existing seal unreconstructible — not "fail to verify",
// unreconstructible, because the key is not stored anywhere else. It
// therefore requires a new commitmentVersion, a new keyCommitmentTag, and a
// verifier that dispatches on the version of the seal it is checking.
func CommitKey(seal SealID, generation Generation, key SealedKey) KeyCommitment {
	h := sha256.New()

	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(keyCommitmentTag)))
	h.Write(length[:])
	h.Write([]byte(keyCommitmentTag))
	h.Write([]byte{commitmentVersion})

	binary.BigEndian.PutUint64(length[:], uint64(len(seal.s)))
	h.Write(length[:])
	h.Write([]byte(seal.s))

	var gen [4]byte
	binary.BigEndian.PutUint32(gen[:], uint32(generation))
	h.Write(gen[:])

	binary.BigEndian.PutUint64(length[:], uint64(len(key.b)))
	h.Write(length[:])
	h.Write(key.b)

	var c KeyCommitment
	h.Sum(c[:0])
	return c
}

// Equal reports whether c and other are the same commitment, compared in
// constant time.
//
// A commitment is not a secret, so the timing of a mismatch leaks nothing
// worth having. The constant-time comparison is here because this is the
// comparison that decides whether a reconstructed key is returned or
// refused, and a uniform habit at that site is cheaper to keep than a
// case-by-case argument about which comparison could ever be in a loop an
// attacker times.
func (c KeyCommitment) Equal(other KeyCommitment) bool {
	return subtle.ConstantTimeCompare(c[:], other[:]) == 1
}

// IsZero reports whether c is the reserved zero commitment: no commitment at
// all.
func (c KeyCommitment) IsZero() bool { return c == KeyCommitment{} }

// String returns the commitment as 64 lowercase hex characters. It is not a
// secret; it is the value an operator compares across a seal record and a
// ceremony receipt.
func (c KeyCommitment) String() string { return hex.EncodeToString(c[:]) }

// ParseKeyCommitment parses s as 64 lowercase hex characters. Uppercase is
// rejected rather than normalized, for the same reason ParseSealID rejects
// it: the canonical spelling is the one the record holds.
func ParseKeyCommitment(s string) (KeyCommitment, error) {
	var c KeyCommitment
	if len(s) != 2*sha256.Size {
		return KeyCommitment{}, invalidf(ErrInvalidArgument, "commitment is %d characters, want %d", len(s), 2*sha256.Size)
	}
	if !isLowerHex(s) {
		return KeyCommitment{}, invalidf(ErrInvalidArgument, "commitment is not lowercase hex")
	}
	if _, err := hex.Decode(c[:], []byte(s)); err != nil {
		return KeyCommitment{}, invalidf(ErrInvalidArgument, "commitment is not hex")
	}
	return c, nil
}

// KeyCommitmentFrom returns the commitment held in b, which must be exactly
// sha256.Size bytes.
//
// It exists because the Postgres adapter maps the commitment column to
// bytea and therefore to []byte: pgx has no scan plan from bytea into a
// fixed-size array, and the only way to give it one is sql.Scanner and
// driver.Valuer on this type — which CONVENTIONS.md forbids on a
// security-relevant value, because those methods are exported and would let
// any package construct a commitment from arbitrary bytes. So the column
// maps to its primitive and the adapter converts through this constructor,
// which rejects a wrong length instead of truncating.
func KeyCommitmentFrom(b []byte) (KeyCommitment, error) {
	if len(b) != sha256.Size {
		return KeyCommitment{}, invalidf(ErrInvalidArgument, "commitment is %d bytes, want %d", len(b), sha256.Size)
	}
	var c KeyCommitment
	copy(c[:], b)
	return c, nil
}

// HolderKind says who holds a custodian's share: a human outside the
// deployment, or the deployment itself.
//
// The distinction is the one charter property 1 is about, which is why it is
// a field on every custodian rather than a separate list of system shares. A
// seal's safety is a property of the *distribution* of its shares, so the
// distribution has to be visible in the record a reviewer reads.
type HolderKind string

const (
	// HolderExternal is a custodian whose share lives outside the
	// deployment: in a safe, with a lawyer, on a hardware token. N−1 shares
	// are of this kind, and their being outside is what makes the sealed
	// thing survive the deployment's death.
	HolderExternal HolderKind = "external"

	// HolderSystem is the deployment itself, holding its single share. At
	// most MaxSystemHeldShares custodians of a seal may be of this kind, and
	// its share is the one a liveness lapse releases.
	HolderSystem HolderKind = "system"
)

// Validate reports whether h is one of the two kinds. The set is closed: a
// third kind of holder would be a third answer to "is this share inside the
// deployment", and that question has two answers.
func (h HolderKind) Validate() error {
	switch h {
	case HolderExternal, HolderSystem:
		return nil
	default:
		return invalidf(ErrInvalidArgument, "holder kind %q is neither %q nor %q", string(h), HolderExternal, HolderSystem)
	}
}

// String returns the holder kind unchanged.
func (h HolderKind) String() string { return string(h) }

// Custodian is one named holder of one share.
//
// A custodian is a name and a position, and nothing else. There is no
// contact detail here, no role, no relationship to the principal and no
// instruction — all of which are things a deployment knows and this module
// must not, per CHARTER.md's "any domain concept, or any knowledge of what
// the sealed thing is". What the module does need is which share is whose,
// so that a release names a person rather than an index.
type Custodian struct {
	// ID names the custodian, opaquely. Required.
	ID CustodianID
	// Holder says whether the share is inside the deployment or outside it.
	// Required.
	Holder HolderKind
	// Index is which of the seal's shares is this custodian's, 1..Total.
	// Required.
	Index ShareIndex
}

// Validate reports whether c is well-formed in itself. Whether its index
// fits its seal's threshold, and whether its holder kind is permitted
// alongside the others, are Seal.Validate's questions.
func (c Custodian) Validate() error {
	if c.ID.IsZero() {
		return invalidf(ErrInvalidArgument, "custodian names nobody")
	}
	if err := c.Holder.Validate(); err != nil {
		return err
	}
	return c.Index.Validate()
}

// Seal is one sealed key's record: everything about the custody arrangement
// except the key itself and the shares themselves.
//
// It is the record a ceremony is run against, and it is deliberately
// sufficient on its own: the threshold, the commitment, who holds which
// share, and the liveness schedule are all here, so a custodian who cannot
// ask the author can read the arrangement out of one row. The key is not
// here and never was — it exists only as shares, which is the whole point.
type Seal struct {
	// Tenant is the tenant this seal belongs to. Required, and the column
	// every row-level-security policy in this module's schema is keyed on.
	Tenant TenantID
	// ID names this seal globally and permanently. Required.
	ID SealID
	// Generation is which sealing this record describes. A re-seal advances
	// it and mints a new key, so a share of an earlier generation is useless
	// against this record — see Generation.
	Generation Generation
	// Threshold is the M-of-N this generation was cut under. It may change
	// across a re-seal: changing custodians is one of the reasons to
	// re-seal.
	Threshold Threshold
	// Commitment binds this record to the exact key this generation sealed.
	// Required, and the value reconstruction verifies against — see
	// KeyCommitment.
	Commitment KeyCommitment
	// Custodians names who holds which share. Exactly Threshold.Total of
	// them, with distinct ids and distinct indices covering 1..Total, and at
	// most MaxSystemHeldShares of kind HolderSystem.
	Custodians []Custodian
	// Liveness is the dead-man's-switch schedule: how long between required
	// proofs of life, how notification escalates when one is late, and how
	// long the grace period is. See LivenessSchedule, and Evaluate for what
	// a lapse does and does not release.
	Liveness LivenessSchedule
	// CreatedAt is when the seal was first created, and does not change
	// across a re-seal. SealedAt is when *this generation* was sealed. Both
	// are UTC at microsecond precision — see CanonicalTime.
	CreatedAt time.Time
	SealedAt  time.Time
}

// SystemHeldShares returns how many of the seal's shares the deployment
// holds. It is the left-hand side of charter property 1, and
// Seal.Validate's job is to keep it below Threshold.Required.
func (s Seal) SystemHeldShares() int {
	n := 0
	for _, c := range s.Custodians {
		if c.Holder == HolderSystem {
			n++
		}
	}
	return n
}

// IsSystemSufficient reports whether the shares the deployment holds would
// on their own reach the threshold. It must always be false, for every seal
// this module will store, and Validate is what makes that so.
//
// It exists as a method rather than only as a validation branch because it
// is the module's central claim, and a claim that is only a branch inside a
// validator cannot be asserted by a test over every threshold the API
// accepts. escrowtest's SystemSharesAreNeverSufficient is that test.
func (s Seal) IsSystemSufficient() bool {
	return s.SystemHeldShares() >= s.Threshold.Required
}

// Validate reports whether s is a seal this module will store. It checks
// structure and the safety properties that are properties of the record:
// identifiers present, the threshold acceptable, a commitment present,
// exactly Total custodians with distinct ids and distinct non-zero share
// indices, at most MaxSystemHeldShares of them inside the deployment, the
// deployment's share set insufficient, a valid liveness schedule, and
// canonical instants.
//
// It deliberately does **not** require the indices to cover 1..Total. A
// ShareIndex is the x-coordinate of a point on the polynomial, chosen by the
// splitter, and a measured split of 5 shares produced indices
// [227 56 135 108 210] — see docs/superpowers/spikes/2026-10-23-shamir-library.
// An earlier draft of this method required 1..Total and would have rejected
// every real split.
//
// It does not check the commitment against anything — a commitment can only
// be checked by reconstructing, which needs shares this record does not hold.
// That asymmetry is the module working as intended.
func (s Seal) Validate() error {
	if s.Tenant.IsZero() {
		return invalidf(ErrInvalidArgument, "seal names no tenant")
	}
	if s.ID.IsZero() {
		return invalidf(ErrInvalidArgument, "seal names no seal id")
	}
	if err := s.Generation.Validate(); err != nil {
		return err
	}
	if err := s.Threshold.Validate(); err != nil {
		return err
	}
	if s.Commitment.IsZero() {
		return invalidf(ErrInvalidArgument, "seal %s carries no key commitment: its reconstruction could not be verified", s.ID)
	}
	if err := s.validateCustodians(); err != nil {
		return err
	}
	if err := s.Liveness.Validate(); err != nil {
		return err
	}
	return s.validateInstants()
}

// validateCustodians checks the custodian set and, with it, charter property
// 1 as a property of the record.
func (s Seal) validateCustodians() error {
	if len(s.Custodians) != s.Threshold.Total {
		return invalidf(ErrInvalidArgument, "seal %s names %d custodians for a %s threshold: every share has exactly one named holder",
			s.ID, len(s.Custodians), s.Threshold)
	}

	ids := make(map[CustodianID]struct{}, len(s.Custodians))
	indices := make(map[ShareIndex]struct{}, len(s.Custodians))
	for _, c := range s.Custodians {
		if err := c.Validate(); err != nil {
			return err
		}
		if _, dup := ids[c.ID]; dup {
			return invalidf(ErrInvalidArgument, "seal %s names custodian %s twice: a threshold counts distinct custodians, so one person holding two shares is one person holding two votes",
				s.ID, c.ID)
		}
		if _, dup := indices[c.Index]; dup {
			return invalidf(ErrInvalidArgument, "seal %s assigns share index %d twice", s.ID, c.Index)
		}
		ids[c.ID] = struct{}{}
		indices[c.Index] = struct{}{}
	}

	if held := s.SystemHeldShares(); held > MaxSystemHeldShares {
		return invalidf(ErrInvalidArgument, "seal %s puts %d shares inside the deployment, at most %d may be: see CHARTER.md's first safety property",
			s.ID, held, MaxSystemHeldShares)
	}
	if s.IsSystemSufficient() {
		return invalidf(ErrInvalidArgument, "seal %s would let the deployment reach its own %s threshold with the %d share it holds",
			s.ID, s.Threshold, s.SystemHeldShares())
	}
	return nil
}

// validateInstants checks that both instants are present and canonical. They
// have to be canonical rather than merely present because a seal read back
// out of Postgres has microsecond precision, and a record that compared
// unequal to the one that was written would make every round-trip assertion
// in the conformance suite a flake.
func (s Seal) validateInstants() error {
	for _, f := range []struct {
		label string
		at    time.Time
	}{{"created_at", s.CreatedAt}, {"sealed_at", s.SealedAt}} {
		if f.at.IsZero() {
			return invalidf(ErrInvalidArgument, "seal %s has no %s", s.ID, f.label)
		}
		if !f.at.Equal(CanonicalTime(f.at)) {
			return invalidf(ErrInvalidArgument, "seal %s has a non-canonical %s: pass it through CanonicalTime", s.ID, f.label)
		}
	}
	if s.SealedAt.Before(s.CreatedAt) {
		return invalidf(ErrInvalidArgument, "seal %s was sealed before it was created", s.ID)
	}
	return nil
}

// Custodian returns the custodian holding the given share index, and whether
// there is one.
func (s Seal) Custodian(index ShareIndex) (Custodian, bool) {
	for _, c := range s.Custodians {
		if c.Index == index {
			return c, true
		}
	}
	return Custodian{}, false
}

// SystemCustodian returns the custodian representing the deployment itself,
// and whether the seal has one. A seal may legitimately have none — every
// share outside the deployment is a stronger arrangement, not a broken one —
// in which case a liveness lapse has no share to release and the switch is
// informational.
func (s Seal) SystemCustodian() (Custodian, bool) {
	for _, c := range s.Custodians {
		if c.Holder == HolderSystem {
			return c, true
		}
	}
	return Custodian{}, false
}

// AcceptsHeldShare reports whether share is the share the deployment may
// hold for this seal, returning a wrapped sentinel naming the reason when it
// is not.
//
// It is a method on Seal rather than a check inside each store because it is
// three charter properties as preconditions, and every adapter has to apply
// exactly the same three — a store that applied two of them would pass most
// of the conformance suite:
//
//   - the generation must be the seal's current one, or the deployment would
//     be holding a share against a commitment it cannot satisfy (property 4,
//     ErrForeignShare);
//   - the seal must name a custodian inside the deployment at all, because a
//     seal all of whose shares are outside it holds none (ErrInvalidArgument);
//   - the index must be *that* custodian's. A share assigned to a lawyer
//     turning up in the deployment's own storage is the distribution of
//     shares silently changing, and the distribution is what keeps the
//     deployment insufficient (property 1, ErrInvalidArgument).
//
// It does not ask whether a share is already held: that is a question about
// the store's contents, not about the seal, and it is ErrShareAlreadyHeld.
func (s Seal) AcceptsHeldShare(share Share) error {
	if share.Seal() != s.ID {
		return invalidf(ErrForeignShare, "share is of seal %s, not %s", share.Seal(), s.ID)
	}
	if share.Generation() != s.Generation {
		return invalidf(ErrForeignShare, "share of seal %s is %s, the seal is at %s", s.ID, share.Generation(), s.Generation)
	}
	system, ok := s.SystemCustodian()
	if !ok {
		return invalidf(ErrInvalidArgument, "seal %s names no custodian inside the deployment, so the deployment holds no share of it", s.ID)
	}
	if share.Index() != system.Index {
		return invalidf(ErrInvalidArgument, "share index %d of seal %s is %s's, not the deployment's",
			share.Index(), s.ID, s.custodianAt(share.Index()))
	}
	return nil
}

// custodianAt names whoever holds the share at index, for an error message
// that tells an operator whose share was nearly stored in the wrong place.
// It returns a placeholder rather than failing when the index belongs to
// nobody, because its only caller is already constructing an error.
func (s Seal) custodianAt(index ShareIndex) string {
	if c, ok := s.Custodian(index); ok {
		return "custodian " + c.ID.String()
	}
	return "nobody"
}

// Clone returns a deep copy of s, with the custodian and escalation slices
// copied rather than aliased. A store that hands a caller a seal it also
// holds must clone it, or a caller mutating the slice in place could change
// a stored record's custody arrangement.
func (s Seal) Clone() Seal {
	out := s
	if s.Custodians != nil {
		out.Custodians = make([]Custodian, len(s.Custodians))
		copy(out.Custodians, s.Custodians)
	}
	out.Liveness = s.Liveness.Clone()
	return out
}
