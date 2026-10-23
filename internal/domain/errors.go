// This file declares the module's complete error taxonomy.
//
// Two rules govern every error in this module, and both come from the
// charter rather than from style:
//
//   - **No error ever reproduces key material or share bytes**, or any
//     encoding of either, or their length. The release and unseal paths are
//     the ones that hold both, and an error string is the value most likely
//     to reach a log file somebody else can read. Errors name the seal, the
//     generation and the share index — identifiers the caller already
//     holds — and nothing else. See escrowtest's NoSecretLeaksInAnyRendering
//     and NoShareMaterialLeaksInErrors subtests.
//   - **A failure to release is never reported as a success, and an
//     unverified key is never returned as a key.** Plain Shamir
//     reconstruction is malleable: a corrupted share yields a wrong key with
//     no error at all. ErrReconstructionUnverified is the sentinel that
//     exists so that outcome has a name, and internal/threshold is where it
//     is raised.

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidConfig means the module was wired up wrongly and no retry will
// help: a store opened with no tenant, a migration pointed at a database it
// does not fit, a nil handle. It is the "fix the deployment" sentinel, as
// distinct from ErrUnavailable's "try again".
var ErrInvalidConfig = errors.New("escrow: invalid configuration")

// ErrInvalidArgument is returned when an argument is unusable in a way that
// is a bug at the call site rather than a property of the stored state: a
// zero seal id, a proof of life belonging to another seal, a ceremony with
// no participants.
var ErrInvalidArgument = errors.New("escrow: invalid argument")

// ErrMalformedID is returned by every ParseXxxID when a string is not a
// canonical identifier of that kind. The identifier types in this module are
// opaque structs precisely so that this is the only way to obtain one — see
// ids.go.
var ErrMalformedID = errors.New("escrow: malformed id")

// ErrInvalidThreshold is returned by Threshold.Validate. It is a separate
// sentinel from ErrInvalidArgument because a rejected threshold is the one
// argument error that is also a safety property: the lower bound on the
// required count is what makes the system's single share insufficient, so a
// caller that catches this is catching an attempt to create a seal the
// deployment could open alone. See Threshold.
var ErrInvalidThreshold = errors.New("escrow: invalid threshold")

// ErrInvalidSchedule is returned by LivenessSchedule.Validate: a
// non-positive check-in interval, escalations that do not advance, fewer
// than MinEscalationChannels independent channels, or a non-positive grace
// period.
//
// It is its own sentinel for the same reason ErrInvalidThreshold is. The
// charter requires escalating notification over multiple independent
// channels and a grace period any single proof of life cancels; a schedule
// that does not express that is not a less convenient schedule, it is a
// dead-man's switch that can misfire, and the type refuses to hold one.
var ErrInvalidSchedule = errors.New("escrow: invalid liveness schedule")

// ErrInvalidKeyMaterial is returned when a buffer offered as a key is not
// usable key material: the wrong length, empty, or all-zero.
var ErrInvalidKeyMaterial = errors.New("escrow: invalid key material")

// ErrInvalidShare is returned when a share is not structurally usable: no
// seal, no material, a material length that does not match KeySize, or an
// index of zero. It says nothing about whether the share is one of this
// seal's shares — that is ErrForeignShare — nor whether it is intact, which
// only ErrReconstructionUnverified can answer.
var ErrInvalidShare = errors.New("escrow: invalid share")

// ErrSealExists is returned by CreateSeal when the seal is already stored. A
// seal is created once and rotated thereafter; overwriting one would discard
// the commitment that distributed shares were cut against, which is the one
// value in the record that cannot be reconstructed from anything else.
var ErrSealExists = errors.New("escrow: seal already exists")

// ErrSealNotFound is returned when no seal with that id is stored for this
// tenant. It deliberately does not distinguish "no such seal" from "not
// yours": a store is opened scoped to one tenant, and a caller that could
// tell the two apart could enumerate another tenant's seal ids.
var ErrSealNotFound = errors.New("escrow: seal not found")

// ErrShareAlreadyHeld is returned by HoldShare when the system already holds
// a share for that seal.
//
// This is charter property 1 as a sentinel. The system holds at most one
// share and is never sufficient; a second share in the deployment would make
// the deployment two steps closer to being able to unseal on its own, and
// for a 2-of-N seal it would make it sufficient outright. The port offers no
// way to express holding two — HeldShare returns one share, not a slice —
// and the stores refuse the attempt rather than overwriting, because
// overwriting would silently destroy the share a custodian may already have
// been told the system holds.
var ErrShareAlreadyHeld = errors.New("escrow: a share is already held for this seal")

// ErrNoHeldShare is returned when the system holds no share for that seal.
// It is an ordinary state, not a malfunction: a seal whose every share went
// to an external custodian is a stronger seal, not a broken one.
var ErrNoHeldShare = errors.New("escrow: no share is held for this seal")

// ErrForeignShare is returned by Reconstruct when a presented share does not
// belong to the seal and generation being reconstructed.
//
// It is the first line of defence for charter property 4 and the cheap half
// of it: a share carries the seal id and generation it was cut under, so a
// share from a previous generation is rejected by inspection before any
// arithmetic happens. The expensive half — a share whose binding has been
// rewritten to claim the new generation — is caught by the commitment, as
// ErrReconstructionUnverified. Both halves are tested, because only the
// second one is a real guarantee.
var ErrForeignShare = errors.New("escrow: share does not belong to this seal and generation")

// ErrDuplicateShare is returned by Reconstruct when two presented shares
// carry the same index.
//
// Lagrange interpolation over duplicated points does not have more
// information than over one of them; depending on the implementation it
// either divides by zero or silently produces a wrong answer. Either way,
// accepting duplicates would let a single custodian appear to satisfy an
// M-of-N threshold by presenting one share M times, which is the whole
// threshold defeated by a copy-paste. The count that matters is distinct
// custodians, so duplicates are refused before they are counted.
var ErrDuplicateShare = errors.New("escrow: duplicate share index")

// ErrInsufficientShares is returned by Reconstruct when fewer than the
// seal's required number of distinct shares were presented. It is refused
// before any arithmetic: plain Shamir does not report "not enough points",
// it interpolates whatever it was given and returns a wrong key.
var ErrInsufficientShares = errors.New("escrow: not enough shares to reach the threshold")

// ErrReconstructionUnverified is the sentinel this module exists to be able
// to return.
//
// Shamir's scheme is not authenticated. Given enough points it interpolates
// a value, and if one of those points is corrupted or fabricated it
// interpolates a *different* value and reports nothing — a wrong key,
// silently, which a caller would then use to decrypt and get garbage, or
// worse, store as if it were the key. So every seal records a commitment to
// the key it sealed (see KeyCommitment), and reconstruction compares the
// value it interpolated against that commitment and returns this error, and
// no key, when they differ.
//
// What it does not tell the caller, deliberately: which share was wrong. The
// commitment is over the key, so a mismatch localizes to nothing smaller
// than "the set you presented". Naming a suspect would be a guess, and a
// wrong guess about which custodian supplied a bad share is worse than no
// guess at all.
var ErrReconstructionUnverified = errors.New("escrow: reconstructed key failed its commitment")

// ErrUnavailable means the store is reachable in principle but was not
// reachable, or not usable, just now: a refused connection, a lock held by
// another process, a transaction Postgres asked the caller to retry. It is
// the one sentinel here that invites a retry.
var ErrUnavailable = errors.New("escrow: store unavailable")

// ErrStorage means the store refused or failed the operation for a reason
// that is neither configuration nor transient: a constraint it would not let
// us satisfy, a row that would not scan, a privilege that is not held.
//
// Errors wrapping it never carry the database's own message text. Postgres
// echoes offending values into some of its messages, and one of the columns
// involved here holds a share's material — so an adapter maps a SQLSTATE
// onto a sentinel and drops everything the database said. Migration errors
// are the deliberate exception: they are about DDL rather than rows, nothing
// in them has seen a share, and an operator needs to know what Postgres
// actually objected to.
var ErrStorage = errors.New("escrow: store rejected the operation")

// invalidf is the one place a wrapped validation error is formatted, so that
// every validation failure in this package reads the same and none of them
// can accidentally be handed a secret to interpolate: the only arguments any
// caller passes are identifiers, counts and durations.
func invalidf(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}
