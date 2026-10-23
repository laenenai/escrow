// This file is the dead-man's switch, and it is a pure function.
//
// Evaluate maps (schedule, proofs of life, now) onto a state and the
// notifications that are due. It reads no clock, starts no goroutine, holds
// no timer, performs no I/O and mutates nothing — the instant is a
// parameter, which is the entire reason the most dangerous logic in the
// module is testable at all. A daemon calls it on a tick; a test calls it on
// a hundred thousand generated timelines.
//
// # Why the shape matters more than the logic
//
// CHARTER.md: "This is the one mechanism in the system where a false
// positive is **unrecoverable**: releasing a will while its author is alive
// cannot be undone." A false positive here is a state machine that says
// Lapsed when the principal is alive. Three design choices follow, and none
// of them is about convenience:
//
//  1. **The state is derived, never stored.** There is no "notified" flag to
//     get stale, no timer that fired while the process was down, no
//     accumulated counter to drift. Everything is recomputed from the most
//     recent proof of life, so the only way to be in the wrong state is to
//     have the wrong proofs — and the proofs are an append-only record.
//     A daemon that crashes between stage 2 and stage 3 re-derives stage 3
//     on restart; one that keeps its position in memory does not.
//  2. **A lapse releases a share, not the content.** Evaluate's result has
//     no path to a key: the strongest thing it can say is Effect() ==
//     EffectShareRelease, which releases the deployment's single share —
//     and charter property 1 guarantees that share is below the threshold.
//     So a false positive costs one share, which is exactly the cost the
//     charter says it should cost, and still requires named humans to act.
//  3. **Any single proof of life cancels everything.** Because the whole
//     timeline is derived from max(proofs), one proof moves the deadline,
//     every escalation and the lapse instant forward together. There is no
//     "cancel" operation that could be forgotten, no grace period that
//     continues running once a proof arrives. A hospital stay, a sabbatical
//     or a lost phone ends the escalation by the principal doing the one
//     thing they are able to do.
//
// # The timeline
//
// Let last be the most recent proof of life, or LivenessSchedule.Since if
// there is none yet. Then:
//
//	last ──CheckIn──▶ deadline ──Escalations[i].After──▶ notification i
//	                           ──Escalations[last].After──▶ graceStart
//	                                      ──Grace──▶ lapsesAt
//
//	        │ now < deadline   │ StateAlive    │ nothing is due
//	        │ now < graceStart │ StateOverdue  │ escalations due so far
//	        │ now < lapsesAt   │ StateGrace    │ every escalation is due
//	        │ otherwise        │ StateLapsed   │ one share is released
//
// Because lapsesAt is strictly after graceStart, which is at or after every
// notification's due instant, **a lapse is unreachable until every
// escalation in the schedule has become due.** That is charter property 3's
// "notification runs over multiple independent channels before the
// threshold", and LivenessSchedule.Validate's refusal of a schedule with
// fewer than MinEscalationChannels distinct channels is the other half of
// it.

package domain

import "time"

// MinEscalationChannels is how many independent notification channels a
// liveness schedule must escalate over before a lapse can be reached: 2.
//
// It is a constant rather than a recommendation because of what the charter
// says the channels are for: "A hospital stay, a sabbatical or a lost phone
// must not release anything." Every one of those examples is a *single
// channel* becoming unavailable while the principal is perfectly alive. A
// schedule with one channel is therefore not a schedule with less
// redundancy, it is a dead-man's switch whose trigger condition includes
// "the principal changed phone number", and LivenessSchedule.Validate
// refuses to hold one.
//
// Two is the floor, not the recommendation. Three independent channels — one
// of which is not a device the principal carries — is what the procedure
// documentation will recommend when it lands.
const MinEscalationChannels = 2

// Escalation is one step of the notification ladder: how long after the
// check-in deadline to notify, and on which channel.
type Escalation struct {
	// After is how long after the check-in deadline this notification
	// becomes due. Zero means "at the deadline". Must be non-negative, and
	// strictly greater than the previous escalation's — see
	// LivenessSchedule.Validate.
	After time.Duration
	// Channel names the channel to notify on, in the caller's own
	// vocabulary. Required.
	Channel ChannelID
}

// LivenessSchedule is a seal's dead-man's-switch configuration: how often
// the principal must prove they are alive, how notification escalates when
// a proof is late, and how long the cancellable grace period is before the
// deployment's single share is released.
//
// The zero value is not valid. Validate is the authoritative description of
// what is.
type LivenessSchedule struct {
	// Since is the instant the schedule counts from before any proof of
	// life has been recorded: the seal's own sealing instant.
	//
	// It is a field of the schedule rather than a separate argument to
	// Evaluate so that Evaluate's signature stays
	// (schedule, proofs, now) — a function of three things, the third of
	// which is the only clock in sight. A schedule with no origin would
	// either have to invent one or read a clock, and both are the failure
	// modes this file exists to avoid.
	Since time.Time

	// CheckIn is how long a proof of life is good for. The deadline is the
	// most recent proof plus this. Must be positive.
	CheckIn time.Duration

	// Escalations is the notification ladder, in order, each relative to the
	// deadline. At least MinEscalationChannels distinct channels must appear
	// across it, and the offsets must strictly increase.
	//
	// The last escalation's offset is where the grace period starts, so the
	// ladder is always complete before a lapse is reachable.
	Escalations []Escalation

	// Grace is how long after the final escalation the principal still has
	// to cancel everything with a single proof of life. Must be positive: a
	// zero grace period is a switch that fires on the same instant as its
	// last warning, which is a warning nobody can act on.
	Grace time.Duration
}

// Validate reports whether s is a schedule this module will accept, as a
// wrapped ErrInvalidSchedule. Each refusal is a charter property, not a
// style preference — see MinEscalationChannels and the Grace field.
func (s LivenessSchedule) Validate() error {
	if s.Since.IsZero() {
		return invalidf(ErrInvalidSchedule, "no origin: a schedule with no proof of life yet has to count from somewhere")
	}
	if !s.Since.Equal(CanonicalTime(s.Since)) {
		return invalidf(ErrInvalidSchedule, "non-canonical origin: pass it through CanonicalTime")
	}
	if s.CheckIn <= 0 {
		return invalidf(ErrInvalidSchedule, "check-in interval is %s, want a positive duration", s.CheckIn)
	}
	if len(s.Escalations) == 0 {
		return invalidf(ErrInvalidSchedule, "no escalations: a lapse must be preceded by notification over at least %d independent channels",
			MinEscalationChannels)
	}

	channels := make(map[ChannelID]struct{}, len(s.Escalations))
	previous := time.Duration(-1)
	for i, e := range s.Escalations {
		if err := e.Channel.Validate(); err != nil {
			return invalidf(ErrInvalidSchedule, "escalation %d: %v", i+1, err)
		}
		if e.After < 0 {
			return invalidf(ErrInvalidSchedule, "escalation %d is %s after the deadline: an escalation cannot precede the deadline it escalates",
				i+1, e.After)
		}
		if e.After <= previous {
			return invalidf(ErrInvalidSchedule, "escalation %d is %s after the deadline, not later than escalation %d at %s: the ladder must strictly advance, or its stage order is arbitrary",
				i+1, e.After, i, previous)
		}
		previous = e.After
		channels[e.Channel] = struct{}{}
	}
	if len(channels) < MinEscalationChannels {
		return invalidf(ErrInvalidSchedule, "escalates over %d channel(s), want at least %d independent ones: see MinEscalationChannels",
			len(channels), MinEscalationChannels)
	}

	if s.Grace <= 0 {
		return invalidf(ErrInvalidSchedule, "grace period is %s, want a positive duration: a switch that fires on the same instant as its final warning gives nobody a chance to cancel it",
			s.Grace)
	}
	return nil
}

// Span returns how long after the check-in deadline a lapse occurs: the last
// escalation's offset plus the grace period. It is the quantity an operator
// reasoning about "how late can I be" actually wants, and it is derived here
// rather than in three call sites.
func (s LivenessSchedule) Span() time.Duration {
	if len(s.Escalations) == 0 {
		return s.Grace
	}
	return s.Escalations[len(s.Escalations)-1].After + s.Grace
}

// Clone returns a deep copy of s, with the escalation slice copied rather
// than aliased.
func (s LivenessSchedule) Clone() LivenessSchedule {
	out := s
	if s.Escalations != nil {
		out.Escalations = make([]Escalation, len(s.Escalations))
		copy(out.Escalations, s.Escalations)
	}
	return out
}

// ProofOfLife is one recorded demonstration that the principal is alive: an
// instant, the channel it arrived on, and an id so that the same proof
// arriving twice is one record.
//
// What counts as a proof is not this module's business — a signed response,
// a clicked link, a phone call a human logged by hand. The module's business
// is that one of them, at any instant before the lapse, cancels everything.
type ProofOfLife struct {
	// Seal is the seal this proof is for. Required.
	Seal SealID
	// ID names this proof. Required, and minted by NewProofID.
	ID ProofID
	// At is when the principal demonstrated they were alive, UTC at
	// microsecond precision. Required.
	At time.Time
	// Channel is how the proof arrived, in the caller's own vocabulary.
	// Required — a proof whose provenance nobody recorded is the one kind of
	// proof an investigation afterwards cannot assess.
	Channel ChannelID
}

// Validate reports whether p is well-formed enough to record.
func (p ProofOfLife) Validate() error {
	if p.Seal.IsZero() {
		return invalidf(ErrInvalidArgument, "proof of life names no seal")
	}
	if p.ID.IsZero() {
		return invalidf(ErrInvalidArgument, "proof of life for seal %s has no id", p.Seal)
	}
	if err := p.Channel.Validate(); err != nil {
		return err
	}
	if p.At.IsZero() {
		return invalidf(ErrInvalidArgument, "proof of life %s has no instant", p.ID)
	}
	if !p.At.Equal(CanonicalTime(p.At)) {
		return invalidf(ErrInvalidArgument, "proof of life %s has a non-canonical instant: pass it through CanonicalTime", p.ID)
	}
	return nil
}

// Equal reports whether p and other are the same record. Like
// Ceremony.Equal it exists so that a store can tell a redelivery of one
// proof from two different proofs sharing an id — the first is a no-op, the
// second is refused — and == cannot answer that because of the time.Time.
func (p ProofOfLife) Equal(other ProofOfLife) bool {
	return p.Seal == other.Seal && p.ID == other.ID &&
		p.Channel == other.Channel && p.At.Equal(other.At)
}

// LivenessState is where a seal's dead-man's switch has got to. The set is
// closed; see LivenessStates.
type LivenessState string

const (
	// StateAlive means a proof of life is current: the deadline has not
	// passed. Nothing is due and nothing is pending.
	StateAlive LivenessState = "alive"

	// StateOverdue means the deadline has passed and the notification
	// ladder is running. Some escalations are due; the grace period has not
	// started. Nothing has been released and nothing will be until the
	// ladder finishes and the grace period then expires.
	StateOverdue LivenessState = "overdue"

	// StateGrace means every escalation has been due and the final,
	// cancellable window is running. This is the state the charter is most
	// concerned with: one proof of life here returns the seal to StateAlive
	// and costs nothing.
	StateGrace LivenessState = "grace"

	// StateLapsed means the grace period expired with no proof of life, so
	// the deployment's single share is released — the share, not the
	// content. See Liveness.Effect and CHARTER.md's second safety property.
	StateLapsed LivenessState = "lapsed"
)

// LivenessStates returns the closed set of states, in timeline order.
//
// It exists so that the exhaustiveness tests — "no state's effect is an
// unseal", "every state is reachable" — iterate the set rather than a
// hand-written list that a fifth state would not appear in. A new state that
// is not added here fails those tests, which is the intent.
func LivenessStates() []LivenessState {
	return []LivenessState{StateAlive, StateOverdue, StateGrace, StateLapsed}
}

// Notification is one escalation that has become due: which stage, on which
// channel, and the instant it became due.
//
// It is a *statement about the schedule*, not a delivery attempt. Whether it
// was actually delivered is the attempt trail's answer (see Attempt), and
// whether it should be delivered again is the caller's — see Liveness.Due.
type Notification struct {
	// Stage is the escalation's 1-based position in the ladder, so a log
	// line can say "stage 2 of 3" rather than an index.
	Stage int
	// Channel is the channel to notify on.
	Channel ChannelID
	// DueAt is when this notification became due. It is in the past relative
	// to the `now` Evaluate was called with.
	DueAt time.Time
}

// Liveness is Evaluate's answer: the state, the instants the state was
// derived from, and the notifications due as of the instant it was asked
// about.
type Liveness struct {
	// State is where the switch has got to.
	State LivenessState

	// CountingFrom is the instant the timeline was derived from: the most
	// recent proof of life, or the schedule's origin if there is none. It is
	// exposed because "why does it think I am overdue" is the first question
	// anybody asks, and the answer is always this field.
	CountingFrom time.Time

	// Deadline is when the current proof of life expires.
	Deadline time.Time
	// GraceStartsAt is when the final escalation is due and the cancellable
	// window opens.
	GraceStartsAt time.Time
	// LapsesAt is when the deployment's single share is released if no proof
	// of life arrives. It is strictly after GraceStartsAt.
	LapsesAt time.Time

	// Due is every escalation whose due instant is at or before the instant
	// Evaluate was asked about, in stage order. It is the complete set, not
	// the new ones.
	//
	// That is deliberate, and it is what a caller has to understand. Evaluate
	// is pure: it does not know what has already been sent, so it cannot
	// return a delta. A caller achieves at-most-once delivery by diffing this
	// set against its own attempt trail, which is the record that survives a
	// restart. A caller that instead remembered its position in memory would
	// re-notify from stage one after every deploy, and — far worse — would
	// skip a stage entirely if it crashed while holding it.
	Due []Notification
}

// Effect reports what this state releases.
//
// It is EffectShareRelease for StateLapsed and EffectNone for every other
// state, and it is **never** EffectUnseal. That is charter property 2, and
// the reason it is a method here rather than a comment is that a method can
// be asserted over LivenessStates() exhaustively — see the
// LivenessLapseNeverUnseals test. There is no argument a caller can pass, and
// no state a future change can add, that makes a liveness lapse hand back a
// key: the lapse releases the deployment's one share, which charter property
// 1 guarantees is below the threshold, so a named human custodian still has
// to act.
func (l Liveness) Effect() ReleaseEffect {
	if l.State == StateLapsed {
		return EffectShareRelease
	}
	return EffectNone
}

// ShareReleaseDue reports whether the deployment's single share should now be
// released to the seal's custodians.
func (l Liveness) ShareReleaseDue() bool { return l.State == StateLapsed }

// Evaluate derives the liveness state of a schedule from its proofs of life,
// as of now. It is pure: no clock is read, no timer exists, nothing is
// mutated, and the proofs slice is neither sorted nor retained.
//
// It returns a wrapped ErrInvalidSchedule for a schedule that could misfire
// (see LivenessSchedule.Validate) and a wrapped ErrInvalidArgument for a
// zero now or a proof that does not validate. It does **not** check that the
// proofs belong to any particular seal: a caller that mixed two seals' proofs
// would have a bug this function cannot see, so the stores are where a proof
// is bound to a seal and ProofsOfLife is what a caller reads.
//
// # A proof dated in the future is clamped to now, not ignored
//
// A proof whose instant is after now cannot be evidence about the future, and
// there are only three things to do with one: error, ignore it, or clamp it.
//
// Erroring would make a single bad timestamp — a custodian's laptop with a
// skewed clock, a timezone mistake in an integration — turn the whole switch
// into a failed evaluation, and a dead-man's switch that fails to evaluate is
// a dead-man's switch whose state nobody knows.
//
// Ignoring it is the dangerous one. It moves the evaluation toward Lapsed:
// the proof that was offered does not count, so the deadline stays where it
// was, and a release that should have been cancelled is not. Of the two
// failure directions, that is the unrecoverable one.
//
// Clamping treats the proof as "alive, as of now", which is the fail-safe
// direction — and bounds its effect to a single check-in interval, where
// honouring a far-future timestamp would suppress the switch for as long as
// the timestamp was wrong. So: clamped, and the clamping is visible in
// Liveness.CountingFrom, which is never after now.
func Evaluate(s LivenessSchedule, proofs []ProofOfLife, now time.Time) (Liveness, error) {
	if err := s.Validate(); err != nil {
		return Liveness{}, err
	}
	if now.IsZero() {
		return Liveness{}, invalidf(ErrInvalidArgument, "cannot evaluate liveness as of the zero time")
	}
	at := CanonicalTime(now)

	from := s.Since
	for i := range proofs {
		if err := proofs[i].Validate(); err != nil {
			return Liveness{}, err
		}
		observed := proofs[i].At
		if observed.After(at) {
			// Clamped, not ignored. See this function's doc comment: the
			// fail-safe direction is to treat an offered proof as evidence
			// of life now.
			observed = at
		}
		if observed.After(from) {
			from = observed
		}
	}

	last := s.Escalations[len(s.Escalations)-1]
	out := Liveness{
		CountingFrom: from,
		Deadline:     from.Add(s.CheckIn),
	}
	out.GraceStartsAt = out.Deadline.Add(last.After)
	out.LapsesAt = out.GraceStartsAt.Add(s.Grace)

	switch {
	case at.Before(out.Deadline):
		out.State = StateAlive
	case at.Before(out.GraceStartsAt):
		out.State = StateOverdue
	case at.Before(out.LapsesAt):
		out.State = StateGrace
	default:
		out.State = StateLapsed
	}

	for i, e := range s.Escalations {
		dueAt := out.Deadline.Add(e.After)
		if dueAt.After(at) {
			// The ladder's offsets strictly increase, so once one is in the
			// future every later one is too.
			break
		}
		out.Due = append(out.Due, Notification{Stage: i + 1, Channel: e.Channel, DueAt: dueAt})
	}
	return out, nil
}
