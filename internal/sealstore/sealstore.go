// Package sealstore defines the SealStore port — the one place this module
// persists anything — and ships the in-memory adapter the core is
// unit-tested against.
//
// A store is opened scoped to **one tenant**, the way audit's Log is opened
// scoped to one chain. Every method therefore takes a seal id and no tenant
// id, and no call site in this module can pass the wrong tenant because no
// call site names one. The Postgres adapter puts that tenant into the
// session's row-level-security context, so the scoping is enforced by the
// database as well as expressed in the Go API; the in-memory adapter holds
// one tenant's maps and nothing else.
//
// Every adapter must pass escrowtest.RunSealStoreSuite unchanged. **That
// suite, not this interface, is the authoritative description of the
// contract's edge-case behaviour** — in particular of the four refusals that
// are safety properties rather than conveniences, listed below. It lives in
// a sibling package so that a consumer can run it against its own wiring
// without this package dragging testing into every consumer's production
// import graph.
//
// # The port's shape is charter property 1
//
// CHARTER.md's first safety property is that the system holds at most one
// share and is never sufficient. The interesting half of that is structural
// rather than procedural, and it is in this file:
//
//   - **HeldShare returns one share, not a slice.** There is no method that
//     returns the shares the system holds, because there is no plural. A
//     caller cannot iterate them, cannot count them, and cannot write a loop
//     that accumulates them toward a threshold, because the type does not
//     offer the shape such a loop would need.
//   - **HoldShare refuses a second share** with ErrShareAlreadyHeld rather
//     than overwriting. Overwriting would silently destroy a share a
//     custodian may already have been told the system holds; refusing makes
//     the collision a caller's problem at the moment it happens.
//   - The stores make the same thing true physically: the in-memory adapter
//     keys one share per seal, and the Postgres table's primary key is
//     (tenant_id, seal_id), so a second row cannot exist. Not "is rejected"
//     — cannot exist.
//
// Three further refusals are each a charter property as a method
// precondition, and each has its own named subtest in the suite:
//
//   - **HoldShare refuses a share whose index is not the seal's system
//     custodian's.** The system holds the system's share; a share assigned
//     to a lawyer being found in the deployment's own storage is the
//     distribution of shares silently changing, which is the property that
//     keeps the deployment insufficient.
//   - **HoldShare refuses a share from another generation.** Property 4: a
//     re-seal makes old shares useless, and a store that accepted one would
//     be holding a share against a commitment it cannot satisfy.
//   - **ReplaceSeal discards the held share in the same operation.** Also
//     property 4, and the reason it is one operation rather than two: a
//     caller that rotated the seal and then failed before discarding would
//     leave the deployment holding a superseded share, which is both useless
//     and indistinguishable from a current one at a glance.
package sealstore

import (
	"context"

	"github.com/laenenai/escrow/internal/domain"
)

// SealStore is the port every escrow storage adapter implements: seals,
// the single share the deployment may hold, the proofs of life the liveness
// state machine reads, and the ceremony records.
//
// There is deliberately no DeleteSeal. A seal is created once and rotated
// thereafter — see ReplaceSeal — because the record carries the commitment
// that distributed shares were cut against, and that value cannot be
// recovered from anything else once it is gone. Cancelling a seal is a
// re-seal to a key nobody holds shares for, which is charter property 4
// doing the work a delete would do badly.
//
// Every method takes a context as its first argument and must honour a
// cancelled one. An adapter that completed a share release for a request
// that had already gone away would be releasing a share nobody asked for.
type SealStore interface {
	// CreateSeal stores seal, which must validate (see domain.Seal.Validate
	// — it is where charter property 1 is checked against the custodian
	// set) and must be at domain.FirstGeneration. It returns a wrapped
	// domain.ErrSealExists if the seal is already stored, and does not
	// overwrite.
	CreateSeal(ctx context.Context, seal domain.Seal) error

	// Seal returns the stored seal, or a wrapped domain.ErrSealNotFound.
	//
	// The not-found sentinel does not distinguish "no such seal" from "not
	// this tenant's seal", and a store must not let it: a caller that could
	// tell those apart could enumerate another tenant's seal ids by asking.
	Seal(ctx context.Context, id domain.SealID) (domain.Seal, error)

	// ReplaceSeal replaces a stored seal with its next generation, and
	// discards any share the system holds for it, as one atomic operation.
	// It is how a re-seal is persisted.
	//
	// seal must validate, must name an existing seal of this tenant
	// (domain.ErrSealNotFound otherwise), must keep the same CreatedAt, and
	// must be at exactly the stored generation's Next. A generation that
	// skipped a value is refused with a wrapped domain.ErrInvalidArgument:
	// a gap would make a share from the skipped generation indistinguishable
	// from a share of a generation that never existed, and the whole value
	// of the generation field is that a share can be placed in history.
	ReplaceSeal(ctx context.Context, seal domain.Seal) error

	// HoldShare stores the single share the deployment holds for a seal.
	//
	// It refuses, each with its own sentinel:
	//   - a share for a seal that is not stored (domain.ErrSealNotFound);
	//   - a second share for a seal that already has one
	//     (domain.ErrShareAlreadyHeld) — charter property 1;
	//   - a share whose generation is not the stored seal's
	//     (domain.ErrForeignShare) — charter property 4;
	//   - a share whose index is not the seal's system custodian's, or a
	//     share for a seal that has no system custodian at all
	//     (domain.ErrInvalidArgument).
	//
	// The share's material is copied, not retained by reference, so a caller
	// may destroy its own copy immediately afterwards.
	HoldShare(ctx context.Context, share domain.Share) error

	// HeldShare returns the single share the deployment holds for a seal, or
	// a wrapped domain.ErrNoHeldShare.
	//
	// No share is an ordinary state, not a malfunction: a seal every one of
	// whose shares went to an external custodian is a stronger seal, and its
	// dead-man's switch is informational rather than share-releasing.
	//
	// The returned share shares no memory with what the store holds.
	HeldShare(ctx context.Context, id domain.SealID) (domain.Share, error)

	// DiscardHeldShare zeroizes and forgets the share the deployment holds,
	// returning a wrapped domain.ErrNoHeldShare if there is none.
	//
	// It is separate from ReplaceSeal — which discards as part of rotating —
	// because there is a second reason to discard: a deployment reducing its
	// own capability, handing its share to a human and keeping none. That
	// strengthens the seal and must not require a key rotation.
	DiscardHeldShare(ctx context.Context, id domain.SealID) error

	// RecordProofOfLife appends a proof of life for a seal. The proof must
	// validate and must name this seal (domain.ErrInvalidArgument
	// otherwise), and the seal must exist (domain.ErrSealNotFound).
	//
	// Recording the same proof twice — the same id with every field
	// identical — is a no-op and not an error, because the channels a proof
	// arrives on retry: a webhook redelivery must not become two proofs. The
	// same id with any field different is refused, because that is not a
	// retry, it is a bug or a forgery, and silently keeping one of the two
	// would decide which.
	RecordProofOfLife(ctx context.Context, proof domain.ProofOfLife) error

	// ProofsOfLife returns every recorded proof of life for a seal, in
	// ascending instant order, breaking ties by id so that the order is
	// total and the same on every adapter.
	//
	// It returns all of them rather than a page or a window. The liveness
	// state machine only needs the most recent, but a human reconstructing
	// whether a lapse was a false positive needs the pattern, and that is
	// the question this record exists to answer.
	ProofsOfLife(ctx context.Context, id domain.SealID) ([]domain.ProofOfLife, error)

	// RecordCeremony appends a ceremony record for a seal: a release that
	// completed, was refused, or failed.
	//
	// The ceremony must validate, must name this seal, and must not be at a
	// generation ahead of the stored seal's. Recording the same ceremony
	// twice is a no-op when every field is identical and refused otherwise,
	// for the same reason as RecordProofOfLife.
	RecordCeremony(ctx context.Context, ceremony domain.Ceremony) error

	// Ceremonies returns every recorded ceremony for a seal, in ascending
	// instant order, breaking ties by id.
	//
	// The refusals and the failures are in here with the completions, and
	// that is the point — CHARTER.md: the failed ones "are the interesting
	// signal".
	Ceremonies(ctx context.Context, id domain.SealID) ([]domain.Ceremony, error)
}
