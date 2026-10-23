// Package notify declares the Notifier port: how an escalation reaches the
// principal.
//
// **This package is a port and nothing else in this increment.** There is no
// email adapter, no SMS adapter, no postal adapter and no test double, and
// that is a deliberate scope line rather than an omission — see README.md's
// status section. What is here is the shape a channel must satisfy, written
// now because the liveness state machine produces domain.Notification values
// and a consumer needs to know what it will eventually hand them to.
//
// # Why there is no conformance suite yet
//
// CONVENTIONS.md says every port ships a conformance suite. This one does
// not, and the reason is worth stating rather than leaving as an apparent
// lapse: a suite whose only implementation is a test double written in the
// same commit tests the double. It would be green on the day it was written
// and would tell nobody anything about an SMTP client's retry behaviour,
// about what a gateway does with a 4xx, or about whether a channel can report
// delivery at all.
//
// The suite lands with the first real adapter, and it will be the adapter
// that determines what the suite can honestly demand. What this package does
// commit to in the meantime is the two properties below, which are
// charter-derived rather than implementation-derived, and which the suite
// will assert when it exists.
//
// # The two properties a channel must have, and why
//
// CHARTER.md's third safety property requires escalation over "multiple
// independent channels". Independence is not a property any single adapter
// can have — it is a property of the *set*, and it is the deployment's to
// arrange — but two things follow for each adapter in it:
//
//  1. **A channel must not share a failure mode with the principal's primary
//     device.** Two channels that both end at one phone are one channel. A
//     module cannot check this, so it is stated here and it belongs in the
//     ceremony documentation, which is the next increment.
//  2. **A failure to deliver must be reported, not swallowed.** A
//     notification that silently did not arrive is the precise mechanism by
//     which a dead-man's switch misfires: the principal is alive, was never
//     told to check in, and the grace period runs out anyway. So Notify
//     returns an error, the caller records the failure through the attempt
//     trail (domain.AttemptNotification with domain.AttemptFailed), and a
//     lapse whose notifications all failed is a lapse a human should treat as
//     a false positive.
package notify

import (
	"context"

	"github.com/laenenai/escrow/internal/domain"
)

// Notifier delivers one escalation on one channel.
//
// An adapter is expected to serve a single channel — the channel it names in
// Channel — and a deployment composes the ladder by registering one Notifier
// per channel its schedules escalate over.
//
// # At-most-once is the caller's problem, not the adapter's
//
// Notify is **not** required to be idempotent, and a caller must not assume
// it is. domain.Evaluate is a pure function of (schedule, proofs, now) and
// returns every notification due as of now, not the new ones; deduplication
// is done by the caller diffing that set against the attempt trail, which is
// the record that survives a restart. An adapter asked to deliver the same
// stage twice should deliver it twice: a duplicate warning is harmless and a
// suppressed one is not.
type Notifier interface {
	// Channel is the channel this notifier delivers on, matching the
	// domain.ChannelID a schedule's escalations name. It is a method rather
	// than configuration read by the caller so that a registry of notifiers
	// cannot be built with a key that disagrees with the adapter in it.
	Channel() domain.ChannelID

	// Notify delivers n to the principal of seal.
	//
	// It is given the whole seal rather than a contact address because the
	// address is the deployment's to resolve — this module holds no contact
	// details, per CHARTER.md's exclusion of "any domain concept" — and the
	// seal is what names the principal's custodians and the generation the
	// notification concerns.
	//
	// It must honour a cancelled context, and it must not put key material or
	// share bytes into the message it sends: it is given neither, which is the
	// stronger guarantee, and it must not reach for them.
	//
	// A delivery failure is an error, never a silent success. See this
	// package's doc comment.
	Notify(ctx context.Context, seal domain.Seal, n domain.Notification) error
}
