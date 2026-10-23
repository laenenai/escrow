package domain

import "time"

// Clock abstracts the current time so that a seal's instants, a minted
// identifier's timestamp component, and — most importantly — the liveness
// state machine can be driven deterministically in tests. Nothing in this
// module reads the wall clock except through a Clock it was given, and
// Evaluate does not read one at all: it takes the instant as a parameter.
//
// It is declared here rather than imported from a shared module because
// returning the current time is not something you get subtly wrong, so it
// does not earn a go.mod of its own (see CONVENTIONS.md). Go's structural
// typing means this interface and every sibling module's identical one are
// interchangeable: a SystemClock from anywhere satisfies all of them, at
// zero coupling.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, backed by the real wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
//
// It is not safe for concurrent use, and deliberately not made so: a lock
// here would hide, rather than reveal, a test that depends on the order of
// concurrent clock reads.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock { return &FixedClock{now: t} }

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ Clock = (*FixedClock)(nil)

// CanonicalTime normalizes t to the precision and zone every instant in this
// module is stored, compared and digested at: UTC, truncated to whole
// microseconds.
//
// These are the same three lines as audit.CanonicalTime, copied rather than
// reinvented, with its reasoning: Postgres timestamptz holds microseconds, so
// a value carrying nanoseconds round-trips equal in memory and unequal
// through the database. In this module that would be worse than a failed
// equality check. A liveness deadline is derived from a proof-of-life
// instant, so a proof that read back a few hundred nanoseconds earlier than
// it was written would move a deadline — and the direction of the error is
// not something a caller would ever notice until a dead-man's switch fired
// early. Truncating on the way in makes the round trip exact by
// construction.
//
// Truncate also strips any monotonic reading, which is what keeps a
// time.Now() value and its serialized form comparing equal.
func CanonicalTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}
