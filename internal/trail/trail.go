// Package trail records this module's attempts into an audit log.
//
// CHARTER.md requires "an audit trail of every proof-of-life, notification,
// share release and unseal attempt — including the failed ones, which are the
// interesting signal." This package is the whole of that requirement, and the
// most important thing about it is what it does **not** contain: there is no
// hash chain here, no digest, no sequence number and no verification.
//
// # Why this depends on audit rather than reimplementing it
//
// Tamper-evident append-only logging is `audit`'s charter, and a second
// implementation of it in this module would be a second canonical encoding
// to get wrong — CONVENTIONS.md's test for what deserves a module puts "a
// canonical encoding / hash chain" squarely there, because getting it wrong
// means previously stored data becomes unreadable or tamper-evidence is
// silently lost. So this package maps a domain.Attempt onto an audit.Record
// and appends it, and that is all it does.
//
// It depends on audit's **port**, not on its Postgres adapter: a Trail is
// built around an audit.Log, so a consumer wires the durable chain it already
// has (audit.Open) or an in-memory one for tests (audit.NewMemory), and this
// module links no migration engine of audit's. An audit.Log is bound to one
// chain — one (tenant, pool) — at construction, so a Trail is likewise
// per-tenant, which matches how a SealStore is opened.
//
// # The timestamp belongs to audit, and the attempt's own instant goes in the
// detail
//
// audit assigns an entry's timestamp from the log's own clock, and a caller
// cannot choose it — deliberately, so that nobody can backdate an entry. So
// the instant *this* module observed (domain.Attempt.At) is recorded inside
// the detail payload instead. The two are normally within milliseconds; they
// diverge when an attempt is recorded after a retry, and when they do, the
// trail shows both, which is more useful than either alone.
//
// # Nothing in a recorded attempt is secret
//
// A domain.Attempt has no field that can hold key material or share bytes:
// domain.SealedKey and domain.Share are not assignable to any of them. The
// one field that could be handed something it should not is Reason, which is
// a human-readable note bounded by domain's own limit and documented as never
// carrying material; the detail encoder below writes exactly five named
// fields and nothing reflective, so there is no path by which a struct
// somebody extended later reaches the chain by accident.
package trail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/laenenai/audit"

	"github.com/laenenai/escrow/internal/domain"
)

// subjectKind is what every entry this module writes is *about*: a seal.
//
// audit holds no opinion about event semantics — Action and Outcome are
// opaque strings there, by its charter — so the vocabulary is this module's
// to choose and to keep stable. A consumer querying its audit log for
// everything that happened to a seal does so with
// subject_kind = 'seal' and subject_id = the seal id, and that pair is
// therefore a published interface even though audit never interprets it.
const subjectKind = "seal"

// actionPrefix namespaces this module's actions inside a chain that also
// holds the consumer's own events. "escrow.unseal" cannot collide with a
// consumer's "unseal" or with another module's.
const actionPrefix = "escrow."

// Trail records domain.Attempt values into an audit log.
type Trail struct {
	log audit.Log
}

// New returns a Trail that records into log, which must be an audit.Log
// already scoped to the tenant whose seals this trail concerns.
//
// It returns an error for a nil log rather than accepting one and discarding
// every attempt: a trail that silently records nothing is strictly worse than
// no trail, because the absence of a record would then be evidence of
// nothing having been attempted.
func New(log audit.Log) (*Trail, error) {
	if log == nil {
		return nil, fmt.Errorf("%w: trail: Log is required; a trail that discards attempts is worse than no trail, because an empty trail would read as nothing having been attempted",
			domain.ErrInvalidConfig)
	}
	return &Trail{log: log}, nil
}

// Record appends one attempt to the trail.
//
// It is called on the **failure** paths as well as the success paths, and
// that is the point of it — CHARTER.md calls the failed attempts "the
// interesting signal". A refused unseal, a notification the gateway would not
// accept, and a proof of life for a seal that does not exist are each a
// record, with domain.AttemptRefused or domain.AttemptFailed as the outcome.
//
// The attempt is validated first, so a malformed record is a wrapped
// domain.ErrInvalidArgument and the chain is left exactly as it was.
// Everything else is mapped onto this module's sentinels: audit's
// ErrUnavailable and ErrStorage come through as domain.ErrUnavailable and
// domain.ErrStorage, so a caller branches on one taxonomy rather than on
// which module happened to raise the error. The underlying error stays
// wrapped, because nothing in it has seen a share.
func (t *Trail) Record(ctx context.Context, attempt domain.Attempt) error {
	if err := attempt.Validate(); err != nil {
		return fmt.Errorf("escrow: record attempt: %w", err)
	}

	detail, err := encodeDetail(attempt)
	if err != nil {
		return fmt.Errorf("escrow: record attempt on seal %s: %w", attempt.Seal, err)
	}

	record := audit.Record{
		Actor:   audit.ActorID(attempt.Actor.String()),
		Subject: audit.SubjectRef{Kind: subjectKind, ID: attempt.Seal.String()},
		Action:  audit.Action(actionPrefix + attempt.Kind.String()),
		Outcome: audit.Outcome(attempt.Outcome.String()),
		Detail:  detail,
	}
	if _, err := t.log.Append(ctx, record); err != nil {
		return fmt.Errorf("escrow: record attempt on seal %s: %w", attempt.Seal, classify(err))
	}
	return nil
}

// attemptDetail is the detail payload's shape.
//
// It is a struct and not a map, and json.Marshal over a struct emits fields
// in declaration order, which is what makes the bytes a function of the
// values. A map would make them a function of Go's map iteration, and an
// audit entry's digest commits to the exact submitted bytes — so two
// processes recording the same attempt would produce two different entries.
// (audit's own Record.Detail documentation is where that reasoning is set
// out; this is the consumer side of it.)
//
// Field order is therefore part of the format: reordering these fields
// changes the bytes of every subsequently recorded attempt. That does not
// invalidate anything already written — audit commits to what it was given,
// and nothing here is re-derived later — but it does mean two deployments on
// two versions write two shapes, so a change is a reviewed one.
type attemptDetail struct {
	// Generation is which sealing the attempt concerned. Without it, a trail
	// read after a re-seal cannot tell which arrangement an attempt was made
	// against, which is most of what the trail is read for.
	Generation uint32 `json:"generation"`
	// ObservedAt is the instant this module observed, as distinct from the
	// instant audit recorded. See this package's doc comment.
	ObservedAt string `json:"observed_at"`
	// Channel is the notification or proof-of-life channel, omitted for the
	// kinds that have none.
	Channel string `json:"channel,omitempty"`
	// Ceremony names the ceremony this attempt belonged to, omitted when it
	// belonged to none.
	Ceremony string `json:"ceremony,omitempty"`
	// Reason is the human-readable note on a refusal or a failure. Never key
	// material or share bytes — see domain.Attempt.Reason.
	Reason string `json:"reason,omitempty"`
}

// encodeDetail renders the attempt's non-identifying fields as the detail
// payload. The instant is RFC 3339 with nanosecond resolution over a value
// already truncated to microseconds, so it round-trips exactly and sorts
// lexicographically.
func encodeDetail(attempt domain.Attempt) ([]byte, error) {
	detail := attemptDetail{
		Generation: uint32(attempt.Generation),
		ObservedAt: attempt.At.Format("2006-01-02T15:04:05.000000Z07:00"),
		Channel:    attempt.Channel.String(),
		Reason:     attempt.Reason,
	}
	if !attempt.Ceremony.IsZero() {
		detail.Ceremony = attempt.Ceremony.String()
	}

	b, err := json.Marshal(detail)
	if err != nil {
		// Unreachable for this struct — every field is a string or a uint32 —
		// but an error is returned rather than ignored, because a detail
		// payload that silently became empty would make a recorded attempt
		// unreadable without making it absent.
		return nil, fmt.Errorf("%w: encode attempt detail: %w", domain.ErrInvalidArgument, err)
	}
	return b, nil
}

// classify maps an error out of audit onto this module's taxonomy.
//
// It is a mapping rather than a pass-through because a caller of this module
// should branch on this module's sentinels: a consumer that had to know
// audit's taxonomy to handle a failed trail write would be coupled to a
// module it did not choose to depend on. The original stays wrapped, so
// errors.Is against audit's sentinels still works for a caller that does
// know them.
func classify(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, audit.ErrInvalidRecord), errors.Is(err, audit.ErrInvalidArgument):
		// A record audit refuses is this module having built one wrongly,
		// which is a defect here rather than a condition the caller can act
		// on — reported as an argument error so it is not retried.
		return fmt.Errorf("%w: the audit log refused the record: %w", domain.ErrInvalidArgument, err)
	case errors.Is(err, audit.ErrUnavailable):
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: %w", domain.ErrStorage, err)
	}
}
