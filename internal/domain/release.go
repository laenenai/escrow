// This file declares what a release is: the conditions under which one
// happens, what each condition actually releases, the ceremony record that
// says one happened, and the shape of the attempt trail's events.
//
// # The effect is a function of the condition, which is charter property 2
//
// The charter's second safety property is that a liveness lapse releases a
// *share*, not the content. The way to make that true is not to be careful
// at the call sites; it is to make "what does this release" a total function
// of the condition's kind, declared once, with no argument a caller can pass
// to change it. ReleaseConditionKind.Effect is that function, and
// ReleaseConditionKinds lets a test assert it over the closed set rather
// than over whichever kinds the test's author remembered.
//
// Exactly one kind has EffectUnseal, and it is the one whose precondition
// *is* the threshold: enough distinct custodians presented enough distinct
// shares. Nothing else in the module can produce a key, because nothing else
// in the module has M shares.
//
// # Failed attempts are the record, not the exhaust
//
// CHARTER.md asks for "an audit trail of every proof-of-life, notification,
// share release and unseal attempt — including the failed ones, which are
// the interesting signal." So Attempt has an outcome that is not optional and
// not defaulted, and both Ceremony and Attempt model refusal and failure as
// first-class states rather than as the absence of a success record. A trail
// that only records what worked cannot answer the question anybody actually
// asks of it, which is who tried.

package domain

import "time"

// maxReasonLen bounds a ceremony's or an attempt's human-readable reason:
// 1 KiB. Generous for a sentence, and present to reject a value that would
// otherwise go into a permanently retained record. It is also the field most
// at risk of being handed something it should not carry, which is why its
// documentation says so in two places.
const maxReasonLen = 1024

// ReleaseEffect is what a satisfied release condition actually hands over.
// The set is closed, and its smallness is the point.
type ReleaseEffect string

const (
	// EffectNone means nothing is released. It is the effect of a condition
	// that has not been met, and of every liveness state but StateLapsed.
	EffectNone ReleaseEffect = ""

	// EffectShareRelease means one share is released to the seal's
	// custodians — never the content. It is what a liveness lapse and a
	// custodian's own act produce, and it is why a false positive in the
	// dead-man's switch costs a share rather than a secret: the released
	// share still has to be combined with others, by named humans, before
	// anything can be read.
	EffectShareRelease ReleaseEffect = "share"

	// EffectUnseal means the key itself is reconstructed. Exactly one
	// condition kind has this effect — ReleaseByThreshold — and its
	// precondition is that the threshold has already been reached, so this
	// effect never *causes* a release, it describes one that the custodians
	// have already made possible.
	EffectUnseal ReleaseEffect = "unseal"
)

// String returns the effect unchanged.
func (e ReleaseEffect) String() string { return string(e) }

// ReleaseConditionKind names a circumstance under which something is
// released. The set is closed; see ReleaseConditionKinds.
type ReleaseConditionKind string

const (
	// ReleaseByHumanAct is a named custodian deciding to release their own
	// share: the ordinary case, and the one the ceremony is written for. Its
	// effect is a share release, because a custodian holds a share and that
	// is all they hold.
	ReleaseByHumanAct ReleaseConditionKind = "human_act"

	// ReleaseByThreshold is enough distinct shares having been presented to
	// reconstruct the key. It is the only kind whose effect is an unseal,
	// and it is a *consequence* rather than a trigger: the threshold being
	// reached is what the other kinds build toward.
	ReleaseByThreshold ReleaseConditionKind = "threshold_reached"

	// ReleaseByLivenessLapse is the dead-man's switch having run its full
	// escalation and its grace period with no proof of life. Its effect is a
	// share release — one share, the deployment's own — and CHARTER.md's
	// second safety property is exactly that this is so: "A dead-man's
	// switch that unseals is a dead-man's switch that eventually misfires.
	// One that contributes one share still requires a named human custodian
	// to act, so a false positive costs nothing on its own."
	ReleaseByLivenessLapse ReleaseConditionKind = "liveness_lapse"
)

// ReleaseConditionKinds returns the closed set of release conditions.
//
// It exists for the same reason LivenessStates does: the test that no
// condition other than ReleaseByThreshold can unseal has to iterate the
// kinds, not a list somebody maintains beside them. A fourth kind added
// without an Effect case fails that test rather than silently defaulting.
func ReleaseConditionKinds() []ReleaseConditionKind {
	return []ReleaseConditionKind{ReleaseByHumanAct, ReleaseByThreshold, ReleaseByLivenessLapse}
}

// Effect reports what this kind of condition releases. It is total over
// ReleaseConditionKinds and returns EffectNone for anything else, so an
// unrecognised kind releases nothing rather than defaulting to the most
// permissive answer.
func (k ReleaseConditionKind) Effect() ReleaseEffect {
	switch k {
	case ReleaseByHumanAct, ReleaseByLivenessLapse:
		return EffectShareRelease
	case ReleaseByThreshold:
		return EffectUnseal
	default:
		return EffectNone
	}
}

// Validate reports whether k is one of the known kinds.
func (k ReleaseConditionKind) Validate() error {
	if k.Effect() == EffectNone {
		return invalidf(ErrInvalidArgument, "release condition %q is not one of the known kinds", string(k))
	}
	return nil
}

// String returns the kind unchanged.
func (k ReleaseConditionKind) String() string { return string(k) }

// CeremonyOutcome is how a recorded ceremony ended.
type CeremonyOutcome string

const (
	// CeremonyCompleted means the condition was met and the effect was
	// carried out.
	CeremonyCompleted CeremonyOutcome = "completed"

	// CeremonyRefused means the ceremony was convened and the module
	// declined: not enough distinct shares, a share from a superseded
	// generation, a reconstruction that failed its commitment. These are the
	// records that matter — a refusal is somebody having tried.
	CeremonyRefused CeremonyOutcome = "refused"

	// CeremonyFailed means the ceremony could not be completed for a reason
	// that was nobody's decision: the store was unreachable, a notification
	// could not be delivered. It is distinct from CeremonyRefused because
	// the follow-up action is different — a refusal is investigated, a
	// failure is retried.
	CeremonyFailed CeremonyOutcome = "failed"
)

// CeremonyOutcomes returns the closed set of ceremony outcomes.
func CeremonyOutcomes() []CeremonyOutcome {
	return []CeremonyOutcome{CeremonyCompleted, CeremonyRefused, CeremonyFailed}
}

// Validate reports whether o is one of the known outcomes.
func (o CeremonyOutcome) Validate() error {
	switch o {
	case CeremonyCompleted, CeremonyRefused, CeremonyFailed:
		return nil
	default:
		return invalidf(ErrInvalidArgument, "ceremony outcome %q is not one of the known outcomes", string(o))
	}
}

// String returns the outcome unchanged.
func (o CeremonyOutcome) String() string { return string(o) }

// Ceremony is the record of one occasion on which a release condition was
// evaluated and acted on — CHARTER.md's "released only under a recorded
// ceremony", as a row.
//
// It records the arrangement as it was at the time (the generation, the
// threshold's required count) rather than only a reference to the seal,
// because a seal is re-sealed and a ceremony is not: a reader three years
// later must be able to see that four shares were required *then*, without
// having to reconstruct the seal's history. It records participants by
// custodian id, which is the whole point of custodians being named.
//
// It holds no share and no key, and no field of it may ever carry either —
// see Reason.
type Ceremony struct {
	// Tenant is the tenant whose seal this ceremony concerned. Required.
	Tenant TenantID
	// ID names this ceremony. Required, minted by NewCeremonyID.
	ID CeremonyID
	// Seal is the seal the ceremony concerned, and Generation is which
	// sealing of it. Both required.
	Seal       SealID
	Generation Generation
	// Condition is why the ceremony was convened, and Effect is what that
	// condition releases. Effect is stored rather than derived so that the
	// record remains readable if the mapping ever changes — a historical
	// record must say what happened, not what today's code would do.
	Condition ReleaseConditionKind
	Effect    ReleaseEffect
	// Participants are the custodians who took part, by id. A ceremony with
	// no participants is not a ceremony; even a liveness lapse has one,
	// the system custodian.
	Participants []CustodianID
	// SharesPresented is how many distinct shares were put forward, and
	// SharesRequired is how many the threshold wanted at the time. Both are
	// counts, never the shares.
	SharesPresented int
	SharesRequired  int
	// Outcome is how it ended. Required — a ceremony record with no outcome
	// is the one record that cannot be read later.
	Outcome CeremonyOutcome
	// Reason is a short human-readable note on the outcome, for a refusal or
	// a failure. It must never carry key material, share bytes, or any
	// encoding of either: it is written into a permanently retained record
	// and read by people. In practice a caller puts a sentinel's text here
	// (the sentinels in errors.go are written so that this is safe) and
	// nothing else.
	Reason string
	// At is when the ceremony concluded, UTC at microsecond precision.
	At time.Time
}

// Validate reports whether c is well-formed enough to record.
func (c Ceremony) Validate() error {
	if c.Tenant.IsZero() {
		return invalidf(ErrInvalidArgument, "ceremony names no tenant")
	}
	if c.ID.IsZero() {
		return invalidf(ErrInvalidArgument, "ceremony has no id")
	}
	if c.Seal.IsZero() {
		return invalidf(ErrInvalidArgument, "ceremony %s names no seal", c.ID)
	}
	if err := c.Generation.Validate(); err != nil {
		return err
	}
	if err := c.Condition.Validate(); err != nil {
		return err
	}
	if c.Effect != c.Condition.Effect() {
		return invalidf(ErrInvalidArgument, "ceremony %s records condition %s with effect %q, but that condition's effect is %q",
			c.ID, c.Condition, c.Effect, c.Condition.Effect())
	}
	if len(c.Participants) == 0 {
		return invalidf(ErrInvalidArgument, "ceremony %s names no participants: a release nobody took part in is not a ceremony", c.ID)
	}
	for _, p := range c.Participants {
		if p.IsZero() {
			return invalidf(ErrInvalidArgument, "ceremony %s names an empty participant", c.ID)
		}
	}
	if c.SharesPresented < 0 || c.SharesRequired < 0 {
		return invalidf(ErrInvalidArgument, "ceremony %s records a negative share count", c.ID)
	}
	if err := c.Outcome.Validate(); err != nil {
		return err
	}
	if len(c.Reason) > maxReasonLen {
		return invalidf(ErrInvalidArgument, "ceremony %s has a reason of %d bytes, limit is %d", c.ID, len(c.Reason), maxReasonLen)
	}
	if c.At.IsZero() {
		return invalidf(ErrInvalidArgument, "ceremony %s has no instant", c.ID)
	}
	if !c.At.Equal(CanonicalTime(c.At)) {
		return invalidf(ErrInvalidArgument, "ceremony %s has a non-canonical instant: pass it through CanonicalTime", c.ID)
	}
	return nil
}

// Equal reports whether c and other are the same record, field for field.
//
// It exists because the stores need to tell a *retry* from a *conflict*: the
// same ceremony id recorded again with identical content is a redelivery and
// must be a no-op, while the same id with any field different is a bug or a
// forgery and must be refused rather than silently resolved in favour of one
// of them. == cannot answer that — Ceremony holds a slice and a time.Time —
// so the comparison lives here, once, rather than once per adapter.
func (c Ceremony) Equal(other Ceremony) bool {
	if c.Tenant != other.Tenant || c.ID != other.ID || c.Seal != other.Seal ||
		c.Generation != other.Generation || c.Condition != other.Condition ||
		c.Effect != other.Effect || c.SharesPresented != other.SharesPresented ||
		c.SharesRequired != other.SharesRequired || c.Outcome != other.Outcome ||
		c.Reason != other.Reason || !c.At.Equal(other.At) {
		return false
	}
	if len(c.Participants) != len(other.Participants) {
		return false
	}
	for i := range c.Participants {
		if c.Participants[i] != other.Participants[i] {
			return false
		}
	}
	return true
}

// Clone returns a deep copy of c, with the participant slice copied rather
// than aliased.
func (c Ceremony) Clone() Ceremony {
	out := c
	if c.Participants != nil {
		out.Participants = make([]CustodianID, len(c.Participants))
		copy(out.Participants, c.Participants)
	}
	return out
}

// AttemptKind names what was attempted. The set is closed and covers exactly
// the four things CHARTER.md says the trail must record.
type AttemptKind string

const (
	// AttemptProofOfLife is the principal demonstrating they are alive.
	// Recorded whether or not it was accepted: a rejected proof is how a
	// forged one, or a misconfigured channel, becomes visible.
	AttemptProofOfLife AttemptKind = "proof_of_life"

	// AttemptNotification is one escalation being delivered, or failing to
	// be. The failures are the signal: a notification that could not be
	// delivered is the reason a principal did not know they had to act, and
	// a lapse whose notifications all failed is a lapse that should be
	// treated as a false positive by the humans who read the trail.
	AttemptNotification AttemptKind = "notification"

	// AttemptShareRelease is one share being handed to the seal's
	// custodians, by a human act or by a liveness lapse.
	AttemptShareRelease AttemptKind = "share_release"

	// AttemptUnseal is a reconstruction being attempted. The failed ones
	// matter most in this module: a reconstruction that fails its
	// commitment means somebody presented a share that was not a share, and
	// that is the single most interesting event the trail can hold.
	AttemptUnseal AttemptKind = "unseal"
)

// AttemptKinds returns the closed set of attempt kinds, so the mapping into
// an audit record can be asserted over all of them.
func AttemptKinds() []AttemptKind {
	return []AttemptKind{AttemptProofOfLife, AttemptNotification, AttemptShareRelease, AttemptUnseal}
}

// Validate reports whether k is one of the known kinds.
func (k AttemptKind) Validate() error {
	switch k {
	case AttemptProofOfLife, AttemptNotification, AttemptShareRelease, AttemptUnseal:
		return nil
	default:
		return invalidf(ErrInvalidArgument, "attempt kind %q is not one of the known kinds", string(k))
	}
}

// String returns the kind unchanged.
func (k AttemptKind) String() string { return string(k) }

// AttemptOutcome is how an attempt ended.
type AttemptOutcome string

const (
	// AttemptSucceeded means the attempt did what it set out to do.
	AttemptSucceeded AttemptOutcome = "succeeded"

	// AttemptRefused means this module declined: a share from the wrong
	// generation, too few shares, a reconstruction that failed its
	// commitment, a proof of life for a seal that does not exist.
	AttemptRefused AttemptOutcome = "refused"

	// AttemptFailed means it could not be carried out for a reason that was
	// nobody's decision: a channel that would not accept the message, a
	// store that was unreachable.
	AttemptFailed AttemptOutcome = "failed"
)

// AttemptOutcomes returns the closed set of attempt outcomes.
func AttemptOutcomes() []AttemptOutcome {
	return []AttemptOutcome{AttemptSucceeded, AttemptRefused, AttemptFailed}
}

// Validate reports whether o is one of the known outcomes.
func (o AttemptOutcome) Validate() error {
	switch o {
	case AttemptSucceeded, AttemptRefused, AttemptFailed:
		return nil
	default:
		return invalidf(ErrInvalidArgument, "attempt outcome %q is not one of the known outcomes", string(o))
	}
}

// String returns the outcome unchanged.
func (o AttemptOutcome) String() string { return string(o) }

// Attempt is one event in the trail: what was attempted, against which seal,
// by whom, on which channel where that applies, and how it ended.
//
// It is the *shape* of the trail's events and not the trail itself. This
// module does not implement a hash chain — CHARTER.md puts tamper-evident
// append-only logging in audit, and internal/trail records these through
// audit's Log port. Keeping the shape here, free of any audit import, is what
// lets a consumer that has its own trail record the same events without
// adopting audit, and what keeps this package's dependency list empty.
//
// No field of an Attempt may carry key material or share bytes. Actor,
// Channel and Reason are the three fields that could be handed one by a
// careless call site, and Validate bounds Reason for that reason; the
// material types themselves cannot be assigned to any field here, which is
// the stronger guarantee.
type Attempt struct {
	// Tenant is the tenant whose seal this concerned. Required.
	Tenant TenantID
	// Seal is the seal, and Generation which sealing of it. Both required —
	// an attempt against a generation nobody recorded cannot be assessed
	// after a re-seal.
	Seal       SealID
	Generation Generation
	// Kind is what was attempted; Outcome is how it ended. Both required,
	// and Outcome has no default: see this file's doc comment.
	Kind    AttemptKind
	Outcome AttemptOutcome
	// Actor is who attempted it. For a notification or a liveness-driven
	// release the actor is the deployment itself, named by the seal's system
	// custodian; for a human act it is that custodian.
	Actor CustodianID
	// Channel is the channel involved, for a notification or a proof of
	// life. Empty for a release or an unseal, which have no channel.
	Channel ChannelID
	// Ceremony names the ceremony this attempt belongs to, when it belongs
	// to one. Optional: a proof of life belongs to no ceremony.
	Ceremony CeremonyID
	// Reason is a short human-readable note, for a refusal or a failure.
	// Never key material or share bytes — see Ceremony.Reason.
	Reason string
	// At is when it happened, UTC at microsecond precision.
	At time.Time
}

// Validate reports whether a is well-formed enough to record. It is
// deliberately strict about Outcome and about the channel's presence: the
// trail exists to be read by somebody reconstructing what happened, and a
// record that leaves either question unanswered is the record that makes
// that impossible.
func (a Attempt) Validate() error {
	if a.Tenant.IsZero() {
		return invalidf(ErrInvalidArgument, "attempt names no tenant")
	}
	if a.Seal.IsZero() {
		return invalidf(ErrInvalidArgument, "attempt names no seal")
	}
	if err := a.Generation.Validate(); err != nil {
		return err
	}
	if err := a.Kind.Validate(); err != nil {
		return err
	}
	if err := a.Outcome.Validate(); err != nil {
		return err
	}
	if a.Actor.IsZero() {
		return invalidf(ErrInvalidArgument, "attempt on seal %s names no actor", a.Seal)
	}
	switch a.Kind {
	case AttemptProofOfLife, AttemptNotification:
		if err := a.Channel.Validate(); err != nil {
			return invalidf(ErrInvalidArgument, "a %s attempt must name the channel it used: %v", a.Kind, err)
		}
	case AttemptShareRelease, AttemptUnseal:
		if a.Channel != "" {
			return invalidf(ErrInvalidArgument, "a %s attempt has no channel, but names %q", a.Kind, a.Channel)
		}
	}
	if len(a.Reason) > maxReasonLen {
		return invalidf(ErrInvalidArgument, "attempt on seal %s has a reason of %d bytes, limit is %d", a.Seal, len(a.Reason), maxReasonLen)
	}
	if a.At.IsZero() {
		return invalidf(ErrInvalidArgument, "attempt on seal %s has no instant", a.Seal)
	}
	if !a.At.Equal(CanonicalTime(a.At)) {
		return invalidf(ErrInvalidArgument, "attempt on seal %s has a non-canonical instant: pass it through CanonicalTime", a.Seal)
	}
	return nil
}
