package domain

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// The tests in this file are written the way they are because of what
// CHARTER.md says about this one function: "This is the one mechanism in the
// system where a false positive is **unrecoverable**." A handful of
// worked examples would show that Evaluate behaves as its author expected on
// the timelines its author thought of. What is wanted instead is a set of
// invariants that must hold on *every* timeline, checked against many
// generated ones — written by somebody trying to make the switch misfire.
//
// The generator is a deterministic splitmix64 seeded with a constant, so
// every run exercises the same timelines and a failure is replayable from the
// seed and the case index the failure prints. A time-seeded generator would
// turn a real defect into an intermittent one.

// generatedTimelines is how many random (schedule, proofs, now) triples each
// property is checked against. Large enough that the interesting boundaries —
// now exactly on a deadline, on a grace start, on a lapse instant — are hit
// many times; small enough that the whole file runs in well under a second.
const generatedTimelines = 20000

// TestLivenessPropertiesHoldOnGeneratedTimelines is the core of this file:
// one loop over generated timelines, asserting every invariant on each.
//
// They are in one test rather than one test per property so that a single
// generated timeline is checked against all of them. A timeline that
// satisfies each property in isolation but violates two together is exactly
// the kind of defect a per-property loop would miss.
func TestLivenessPropertiesHoldOnGeneratedTimelines(t *testing.T) {
	t.Parallel()

	rng := newRNG(0x5EA1_0C70_BE12_3456)
	states := make(map[LivenessState]int, len(LivenessStates()))

	for i := range generatedTimelines {
		schedule, proofs, now := generateTimeline(rng)

		got, err := Evaluate(schedule, proofs, now)
		if err != nil {
			t.Fatalf("case %d: Evaluate on a generated timeline: %v", i, err)
		}
		states[got.State]++

		// --- the instants are ordered, and nothing is derived from the
		// future. CountingFrom after now would mean a future-dated proof had
		// been honoured rather than clamped, which is the one input that could
		// suppress the switch indefinitely.
		if got.CountingFrom.After(CanonicalTime(now)) {
			t.Fatalf("case %d: CountingFrom %s is after now %s: a future-dated proof was honoured rather than clamped",
				i, got.CountingFrom, now)
		}
		if !got.Deadline.After(got.CountingFrom) {
			t.Fatalf("case %d: deadline %s is not after CountingFrom %s", i, got.Deadline, got.CountingFrom)
		}
		if got.GraceStartsAt.Before(got.Deadline) {
			t.Fatalf("case %d: grace starts at %s, before the deadline %s", i, got.GraceStartsAt, got.Deadline)
		}
		if !got.LapsesAt.After(got.GraceStartsAt) {
			t.Fatalf("case %d: lapse at %s is not after the grace period started at %s: a grace period nobody can act in",
				i, got.LapsesAt, got.GraceStartsAt)
		}

		// --- CHARTER property 2: no state releases content. Asserted on
		// every generated timeline as well as exhaustively over the state
		// set, because this is the property whose violation is irreversible.
		if effect := got.Effect(); effect == EffectUnseal {
			t.Fatalf("case %d: state %s reports an unseal effect: a liveness lapse must release a share, never the content",
				i, got.State)
		}
		if got.ShareReleaseDue() != (got.State == StateLapsed) {
			t.Fatalf("case %d: state %s reports ShareReleaseDue() == %v", i, got.State, got.ShareReleaseDue())
		}

		// --- while a proof of life is current, nothing has been sent at all.
		if got.State == StateAlive && len(got.Due) != 0 {
			t.Fatalf("case %d: a seal with a current proof of life has %d notifications due", i, len(got.Due))
		}

		// --- CHARTER property 3: escalating notification over multiple
		// independent channels *before* the threshold. A lapse is only
		// reachable once the whole ladder has been due, and the ladder covers
		// at least MinEscalationChannels distinct channels.
		if got.State == StateLapsed {
			if len(got.Due) != len(schedule.Escalations) {
				t.Fatalf("case %d: lapsed with %d of %d escalations due: the switch fired before it finished warning",
					i, len(got.Due), len(schedule.Escalations))
			}
			channels := make(map[ChannelID]struct{}, len(got.Due))
			for _, n := range got.Due {
				channels[n.Channel] = struct{}{}
			}
			if len(channels) < MinEscalationChannels {
				t.Fatalf("case %d: lapsed having notified over %d channel(s), want at least %d",
					i, len(channels), MinEscalationChannels)
			}
			if want := got.CountingFrom.Add(schedule.CheckIn + schedule.Span()); CanonicalTime(now).Before(want) {
				t.Fatalf("case %d: lapsed at %s, before the full check-in and span had elapsed (%s)", i, now, want)
			}
		}

		// --- the due set is a prefix of the ladder, in stage order, and
		// every entry is genuinely in the past.
		for j, n := range got.Due {
			if n.Stage != j+1 {
				t.Fatalf("case %d: notification %d reports stage %d", i, j, n.Stage)
			}
			if n.Channel != schedule.Escalations[j].Channel {
				t.Fatalf("case %d: notification %d is on %q, want %q", i, j, n.Channel, schedule.Escalations[j].Channel)
			}
			if n.DueAt.After(CanonicalTime(now)) {
				t.Fatalf("case %d: notification %d is due at %s, in the future", i, j, n.DueAt)
			}
		}

		// --- it is a pure function: same inputs, same answer, and the
		// caller's slice comes back untouched.
		before := slices.Clone(proofs)
		again, err := Evaluate(schedule, proofs, now)
		if err != nil {
			t.Fatalf("case %d: second Evaluate: %v", i, err)
		}
		if !sameLiveness(got, again) {
			t.Fatalf("case %d: two identical calls disagreed", i)
		}
		if !slices.Equal(before, proofs) {
			t.Fatalf("case %d: Evaluate mutated the caller's proofs", i)
		}

		// --- the order proofs are presented in is not part of the answer. A
		// store returns them sorted; a caller assembling them by hand does
		// not.
		shuffled := slices.Clone(proofs)
		rng.shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		reordered, err := Evaluate(schedule, shuffled, now)
		if err != nil {
			t.Fatalf("case %d: Evaluate on reordered proofs: %v", i, err)
		}
		if !sameLiveness(got, reordered) {
			t.Fatalf("case %d: reordering the proofs changed the answer", i)
		}
	}

	// Every state must actually have been generated, or the properties above
	// were asserted over a timeline space that never reaches the dangerous
	// end of the machine.
	for _, state := range LivenessStates() {
		if states[state] == 0 {
			t.Fatalf("no generated timeline produced state %s: the generator does not reach it, so the properties were not tested there", state)
		}
	}
	t.Logf("%d timelines: %v", generatedTimelines, states)
}

// TestAnySingleProofOfLifeCancels is CHARTER.md's third safety property, and
// the property that a hospital stay, a sabbatical or a lost phone must not
// release anything.
//
// Three assertions over generated timelines:
//
//  1. A proof at `now` always returns the seal to StateAlive, whatever state
//     it was in — including from inside the grace period, which is the case
//     the charter names.
//  2. A proof anywhere inside the check-in window also returns it to
//     StateAlive.
//  3. Adding *any* proof at or before now can never move the seal closer to
//     a lapse. This is the general form of the other two: it means there is
//     no timeline, and no combination of proofs, in which demonstrating you
//     are alive makes things worse.
func TestAnySingleProofOfLifeCancels(t *testing.T) {
	t.Parallel()

	rng := newRNG(0xCA17_CE11_0B0B_7777)
	cancelledFromGrace := 0

	for i := range generatedTimelines {
		schedule, proofs, now := generateTimeline(rng)
		at := CanonicalTime(now)

		base, err := Evaluate(schedule, proofs, now)
		if err != nil {
			t.Fatalf("case %d: Evaluate: %v", i, err)
		}

		// 1. A proof right now cancels everything, from any state.
		withNow, err := Evaluate(schedule, append(slices.Clone(proofs), testProof(rng, at)), now)
		if err != nil {
			t.Fatalf("case %d: Evaluate with a proof at now: %v", i, err)
		}
		if withNow.State != StateAlive {
			t.Fatalf("case %d: a proof of life at the instant of evaluation left the seal %s, want %s",
				i, withNow.State, StateAlive)
		}
		if len(withNow.Due) != 0 {
			t.Fatalf("case %d: a proof of life at the instant of evaluation left %d notifications due", i, len(withNow.Due))
		}
		if base.State == StateGrace {
			cancelledFromGrace++
		}

		// 2. A proof anywhere inside the check-in window cancels too, which is
		// what makes the window a window rather than an instant.
		// CheckIn is positive — a schedule with a non-positive one does not
		// validate — and the remainder is below it, so both conversions are
		// in range.
		window := uint64(schedule.CheckIn)                                       //nolint:gosec // CheckIn > 0, enforced by Validate
		inWindow := at.Add(-time.Duration(rng.next()%window) + time.Microsecond) //nolint:gosec // the remainder is below window, which came from an int64
		if !inWindow.Before(schedule.Since) {
			withWindow, err := Evaluate(schedule, append(slices.Clone(proofs), testProof(rng, CanonicalTime(inWindow))), now)
			if err != nil {
				t.Fatalf("case %d: Evaluate with a proof inside the window: %v", i, err)
			}
			if withWindow.State != StateAlive {
				t.Fatalf("case %d: a proof of life %s before evaluation (check-in is %s) left the seal %s",
					i, at.Sub(inWindow), schedule.CheckIn, withWindow.State)
			}
		}

		// 3. The general form: no proof at or before now makes anything worse.
		extra := testProof(rng, CanonicalTime(at.Add(-time.Duration(rng.next()%uint64(90*24*time.Hour)))))
		withExtra, err := Evaluate(schedule, append(slices.Clone(proofs), extra), now)
		if err != nil {
			t.Fatalf("case %d: Evaluate with an extra proof: %v", i, err)
		}
		if severity(withExtra.State) > severity(base.State) {
			t.Fatalf("case %d: adding a proof of life at %s moved the seal from %s to %s: "+
				"demonstrating you are alive must never advance the switch",
				i, extra.At, base.State, withExtra.State)
		}
		if withExtra.CountingFrom.Before(base.CountingFrom) {
			t.Fatalf("case %d: adding a proof of life moved CountingFrom backwards", i)
		}
	}

	if cancelledFromGrace == 0 {
		t.Fatal("no generated timeline was in the grace period when a proof arrived: " +
			"the case CHARTER.md names was never exercised")
	}
	t.Logf("%d of %d generated timelines were cancelled out of the grace period", cancelledFromGrace, generatedTimelines)
}

// TestAFutureDatedProofIsClampedNotHonoured covers the decision documented on
// Evaluate: a proof whose instant is after now is treated as "alive, as of
// now".
//
// Both halves matter. It must not be *ignored*, because ignoring an offered
// proof moves the evaluation toward a lapse, which is the unrecoverable
// direction. And it must not be *honoured*, because a timestamp that is
// wrong by a year would otherwise suppress the switch for a year.
func TestAFutureDatedProofIsClampedNotHonoured(t *testing.T) {
	t.Parallel()

	rng := newRNG(0xF007_0000_DA7E_1234)
	schedule := testScheduleFor(rng)
	now := CanonicalTime(schedule.Since.Add(schedule.CheckIn + schedule.Span() + 365*24*time.Hour))

	lapsed, err := Evaluate(schedule, nil, now)
	if err != nil {
		t.Fatalf("Evaluate with no proofs: %v", err)
	}
	if lapsed.State != StateLapsed {
		t.Fatalf("a seal with no proof of life for a year is %s, want %s", lapsed.State, StateLapsed)
	}

	for _, ahead := range []time.Duration{time.Microsecond, time.Hour, 365 * 24 * time.Hour, 100 * 365 * 24 * time.Hour} {
		proof := testProof(rng, CanonicalTime(now.Add(ahead)))
		got, err := Evaluate(schedule, []ProofOfLife{proof}, now)
		if err != nil {
			t.Fatalf("Evaluate with a proof %s in the future: %v", ahead, err)
		}
		if got.State != StateAlive {
			t.Fatalf("a proof %s in the future left the seal %s: an offered proof must not be ignored, because ignoring it moves toward a release",
				ahead, got.State)
		}
		if !got.CountingFrom.Equal(now) {
			t.Fatalf("a proof %s in the future set CountingFrom to %s, want now (%s): it was honoured rather than clamped, so its effect is unbounded",
				ahead, got.CountingFrom, now)
		}
		if !got.Deadline.Equal(now.Add(schedule.CheckIn)) {
			t.Fatalf("a proof %s in the future pushed the deadline to %s, want one check-in from now", ahead, got.Deadline)
		}
	}
}

// TestLivenessLapseNeverUnseals asserts CHARTER.md's second safety property
// exhaustively over the closed state set rather than over whichever states a
// test author remembered. A fifth state added without a case in Effect fails
// here.
func TestLivenessLapseNeverUnseals(t *testing.T) {
	t.Parallel()

	for _, state := range LivenessStates() {
		got := Liveness{State: state}.Effect()
		switch state {
		case StateLapsed:
			if got != EffectShareRelease {
				t.Fatalf("state %s has effect %q, want %q: a lapse releases one share", state, got, EffectShareRelease)
			}
		default:
			if got != EffectNone {
				t.Fatalf("state %s has effect %q, want %q", state, got, EffectNone)
			}
		}
		if got == EffectUnseal {
			t.Fatalf("state %s can unseal: a dead-man's switch that unseals is one that eventually misfires", state)
		}
	}

	// And for an unknown state, in case one is ever constructed by a decoder
	// rather than by Evaluate: release nothing, not the most permissive
	// answer.
	if got := (Liveness{State: LivenessState("something_new")}).Effect(); got != EffectNone {
		t.Fatalf("an unrecognised state has effect %q, want %q", got, EffectNone)
	}
}

// TestEvaluateWalksTheWholeTimeline is the worked example beside the
// properties: one schedule, stepped instant by instant across every
// boundary, so that the state machine's shape is readable in a test and not
// only in a doc comment.
func TestEvaluateWalksTheWholeTimeline(t *testing.T) {
	t.Parallel()

	since := CanonicalTime(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	schedule := LivenessSchedule{
		Since:   since,
		CheckIn: 30 * 24 * time.Hour,
		Escalations: []Escalation{
			{After: 0, Channel: "email"},
			{After: 7 * 24 * time.Hour, Channel: "sms"},
			{After: 14 * 24 * time.Hour, Channel: "postal"},
		},
		Grace: 14 * 24 * time.Hour,
	}
	deadline := since.Add(schedule.CheckIn)

	tests := []struct {
		name     string
		now      time.Time
		want     LivenessState
		wantDue  int
		wantLast ChannelID
	}{
		{"the instant it was sealed", since, StateAlive, 0, ""},
		{"a day in", since.AddDate(0, 0, 1), StateAlive, 0, ""},
		{"one microsecond before the deadline", deadline.Add(-time.Microsecond), StateAlive, 0, ""},
		{"exactly on the deadline", deadline, StateOverdue, 1, "email"},
		{"a day overdue", deadline.AddDate(0, 0, 1), StateOverdue, 1, "email"},
		{"the second escalation", deadline.Add(7 * 24 * time.Hour), StateOverdue, 2, "sms"},
		{"a microsecond before the third", deadline.Add(14*24*time.Hour - time.Microsecond), StateOverdue, 2, "sms"},
		{"the third escalation opens the grace period", deadline.Add(14 * 24 * time.Hour), StateGrace, 3, "postal"},
		{"a microsecond before the lapse", deadline.Add(28*24*time.Hour - time.Microsecond), StateGrace, 3, "postal"},
		{"the lapse", deadline.Add(28 * 24 * time.Hour), StateLapsed, 3, "postal"},
		{"long after the lapse", deadline.AddDate(1, 0, 0), StateLapsed, 3, "postal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(schedule, nil, tc.now)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.State != tc.want {
				t.Fatalf("state = %s, want %s", got.State, tc.want)
			}
			if len(got.Due) != tc.wantDue {
				t.Fatalf("%d notifications due, want %d", len(got.Due), tc.wantDue)
			}
			if tc.wantDue > 0 && got.Due[len(got.Due)-1].Channel != tc.wantLast {
				t.Fatalf("last due notification is on %q, want %q", got.Due[len(got.Due)-1].Channel, tc.wantLast)
			}
		})
	}

	// And the same walk with a proof of life halfway through the grace
	// period, which must put every later instant back inside the window.
	t.Run("a proof in the grace period resets the whole timeline", func(t *testing.T) {
		rescue := deadline.Add(21 * 24 * time.Hour)
		proofs := []ProofOfLife{testProof(newRNG(1), CanonicalTime(rescue))}

		got, err := Evaluate(schedule, proofs, deadline.Add(28*24*time.Hour))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if got.State != StateAlive {
			t.Fatalf("state at the would-be lapse instant = %s, want %s", got.State, StateAlive)
		}
		if !got.LapsesAt.Equal(rescue.Add(schedule.CheckIn + schedule.Span())) {
			t.Fatalf("lapse instant = %s, want it moved to one full timeline after the proof", got.LapsesAt)
		}
	})
}

func TestLivenessScheduleValidate(t *testing.T) {
	t.Parallel()

	since := CanonicalTime(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	good := LivenessSchedule{
		Since:   since,
		CheckIn: time.Hour,
		Escalations: []Escalation{
			{After: 0, Channel: "email"},
			{After: time.Minute, Channel: "sms"},
		},
		Grace: time.Hour,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("the baseline schedule does not validate: %v", err)
	}

	tests := map[string]struct {
		mutate func(s *LivenessSchedule)
		want   error
	}{
		"no origin":            {func(s *LivenessSchedule) { s.Since = time.Time{} }, ErrInvalidSchedule},
		"non-canonical origin": {func(s *LivenessSchedule) { s.Since = s.Since.Add(time.Nanosecond) }, ErrInvalidSchedule},
		"zero check-in":        {func(s *LivenessSchedule) { s.CheckIn = 0 }, ErrInvalidSchedule},
		"negative check-in":    {func(s *LivenessSchedule) { s.CheckIn = -time.Hour }, ErrInvalidSchedule},
		"no escalations":       {func(s *LivenessSchedule) { s.Escalations = nil }, ErrInvalidSchedule},
		"one channel only":     {func(s *LivenessSchedule) { s.Escalations[1].Channel = "email" }, ErrInvalidSchedule},
		"a negative offset":    {func(s *LivenessSchedule) { s.Escalations[0].After = -time.Second }, ErrInvalidSchedule},
		"a ladder that does not advance": {func(s *LivenessSchedule) {
			s.Escalations[1].After = s.Escalations[0].After
		}, ErrInvalidSchedule},
		"a ladder that goes backwards": {func(s *LivenessSchedule) {
			s.Escalations[0].After, s.Escalations[1].After = s.Escalations[1].After, s.Escalations[0].After
		}, ErrInvalidSchedule},
		"an empty channel": {func(s *LivenessSchedule) { s.Escalations[0].Channel = "" }, ErrInvalidSchedule},
		"zero grace":       {func(s *LivenessSchedule) { s.Grace = 0 }, ErrInvalidSchedule},
		"negative grace":   {func(s *LivenessSchedule) { s.Grace = -time.Hour }, ErrInvalidSchedule},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := good.Clone()
			tc.mutate(&s)
			if err := s.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
			if _, err := Evaluate(s, nil, since.Add(time.Hour)); !errors.Is(err, tc.want) {
				t.Fatalf("Evaluate error = %v, want %v: an unsafe schedule must not evaluate at all", err, tc.want)
			}
		})
	}
}

func TestEvaluateRefusesBadArguments(t *testing.T) {
	t.Parallel()

	since := CanonicalTime(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	schedule := LivenessSchedule{
		Since:       since,
		CheckIn:     time.Hour,
		Escalations: []Escalation{{After: 0, Channel: "email"}, {After: time.Minute, Channel: "sms"}},
		Grace:       time.Hour,
	}

	if _, err := Evaluate(schedule, nil, time.Time{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Evaluate at the zero time error = %v, want ErrInvalidArgument", err)
	}

	bad := []ProofOfLife{{}}
	if _, err := Evaluate(schedule, bad, since); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Evaluate with an invalid proof error = %v, want ErrInvalidArgument", err)
	}
}

// ---- the generator ----

// rng is a splitmix64. It is written out here rather than taken from
// math/rand so that a generated timeline is reproducible from a constant
// seed with no dependence on the standard library's generator or on a global
// source — and so that a failure can be replayed by anyone who reads the
// seed in this file.
type rng struct{ state uint64 }

func newRNG(seed uint64) *rng { return &rng{state: seed} }

func (r *rng) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// between returns a duration in [lo, hi).
func (r *rng) between(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	// hi > lo is established by the branch above, so the span is positive and
	// the remainder is below it: both conversions are in range.
	span := uint64(hi - lo)                  //nolint:gosec // hi > lo, checked above
	return lo + time.Duration(r.next()%span) //nolint:gosec // the remainder is below span, which came from an int64
}

// intn returns an int in [0, n).
func (r *rng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n)) //nolint:gosec // bounded by n, which is a small test constant
}

// shuffle applies a Fisher-Yates swap sequence of length n through swap.
func (r *rng) shuffle(n int, swap func(a, b int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.intn(i+1))
	}
}

// generatorOrigin is the instant every generated schedule counts from. A
// fixed instant rather than time.Now(), for the same reason the seed is
// fixed.
var generatorOrigin = CanonicalTime(time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC))

// testChannels is the pool generated schedules draw from. Four, so that a
// generated ladder can and does repeat a channel while still covering
// MinEscalationChannels distinct ones.
var testChannels = []ChannelID{"email", "sms", "postal", "second-contact"}

// generateTimeline produces one random (schedule, proofs, now) triple.
//
// The ranges are chosen so that `now` lands in every region of the timeline
// often — before the deadline, between escalations, inside the grace period,
// and past the lapse — which is checked rather than assumed: the properties
// test fails if any state was never generated.
func generateTimeline(r *rng) (LivenessSchedule, []ProofOfLife, time.Time) {
	schedule := testScheduleFor(r)

	proofs := make([]ProofOfLife, 0, 6)
	for range r.intn(6) {
		// Spread over three check-in intervals either side of the origin, so
		// that some proofs are stale, some are current, and some are ahead of
		// `now` and therefore exercise the clamping rule.
		offset := r.between(-2*schedule.CheckIn, 4*schedule.CheckIn)
		proofs = append(proofs, testProof(r, CanonicalTime(schedule.Since.Add(offset))))
	}

	span := schedule.CheckIn + schedule.Span()
	now := CanonicalTime(schedule.Since.Add(r.between(0, 2*span)))
	return schedule, proofs, now
}

// testScheduleFor produces one random schedule that validates.
func testScheduleFor(r *rng) LivenessSchedule {
	ladder := 2 + r.intn(4)
	escalations := make([]Escalation, 0, ladder)
	after := time.Duration(0)
	for i := range ladder {
		if i > 0 {
			after += r.between(time.Hour, 10*24*time.Hour)
		}
		escalations = append(escalations, Escalation{
			After:   after,
			Channel: testChannels[r.intn(len(testChannels))],
		})
	}
	// The generator may have drawn one channel for the whole ladder, which a
	// valid schedule may not have. Forcing the second entry onto a different
	// channel is the smallest repair that keeps every other field random.
	if escalations[1].Channel == escalations[0].Channel {
		escalations[1].Channel = testChannels[(r.intn(len(testChannels)-1)+1+indexOfChannel(escalations[0].Channel))%len(testChannels)]
	}

	return LivenessSchedule{
		Since:       generatorOrigin,
		CheckIn:     r.between(time.Hour, 90*24*time.Hour),
		Escalations: escalations,
		Grace:       r.between(time.Hour, 30*24*time.Hour),
	}
}

func indexOfChannel(c ChannelID) int {
	for i, candidate := range testChannels {
		if candidate == c {
			return i
		}
	}
	return 0
}

// testProof builds a valid proof of life at the given instant. The id is
// derived from the generator rather than minted from a clock, so that a
// generated timeline is fully determined by the seed.
func testProof(r *rng, at time.Time) ProofOfLife {
	id, err := ParseProofID(hexOf(r.next(), r.next()))
	if err != nil {
		// Unreachable: hexOf produces exactly 32 lowercase hex characters.
		// A proof with a zero id would fail Validate inside Evaluate, which
		// is a louder failure than this branch could produce.
		return ProofOfLife{}
	}
	return ProofOfLife{
		Seal:    testSealID(),
		ID:      id,
		At:      at,
		Channel: testChannels[r.intn(len(testChannels))],
	}
}

// testSealID is one fixed seal id. Evaluate does not inspect it — binding a
// proof to a seal is the store's job, as Evaluate's doc comment says — so one
// value is enough and a varying one would imply a check that does not exist.
func testSealID() SealID {
	id, err := ParseSealID("0000000000000000000000000000beef")
	if err != nil {
		return SealID{}
	}
	return id
}

// hexOf renders two uint64s as 32 lowercase hex characters.
func hexOf(hi, lo uint64) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 32)
	for i := range 16 {
		out[15-i] = digits[(hi>>(4*i))&0xF]
		out[31-i] = digits[(lo>>(4*i))&0xF]
	}
	return string(out)
}

// severity orders the states along the timeline, so that "a proof of life
// never makes things worse" is expressible as an inequality.
func severity(s LivenessState) int {
	return slices.Index(LivenessStates(), s)
}

// sameLiveness reports whether two results are identical, comparing instants
// with Equal rather than == so that a monotonic reading could never make two
// equal answers look different.
func sameLiveness(a, b Liveness) bool {
	if a.State != b.State || !a.CountingFrom.Equal(b.CountingFrom) || !a.Deadline.Equal(b.Deadline) ||
		!a.GraceStartsAt.Equal(b.GraceStartsAt) || !a.LapsesAt.Equal(b.LapsesAt) || len(a.Due) != len(b.Due) {
		return false
	}
	for i := range a.Due {
		if a.Due[i].Stage != b.Due[i].Stage || a.Due[i].Channel != b.Due[i].Channel || !a.Due[i].DueAt.Equal(b.Due[i].DueAt) {
			return false
		}
	}
	return true
}
