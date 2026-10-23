package trail_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/audit"

	"github.com/laenenai/escrow"
	"github.com/laenenai/escrow/internal/domain"
)

// TestEveryAttemptKindAndOutcomeReachesTheChain is CHARTER.md's trail
// requirement as a test: "an audit trail of every proof-of-life,
// notification, share release and unseal attempt — including the failed ones,
// which are the interesting signal."
//
// It iterates the closed sets rather than a list of examples, so an attempt
// kind or an outcome added without a mapping fails here.
func TestEveryAttemptKindAndOutcomeReachesTheChain(t *testing.T) {
	t.Parallel()

	// escrow's own FixedClock, not audit's: audit re-exports the FixedClock
	// *type* but not its constructor, so audit.FixedClock is not
	// constructible from outside that module. It does not matter, and the
	// reason it does not is CONVENTIONS.md's Clock decision — the interface is
	// one method, so Go's structural typing makes two independently declared
	// Clocks interchangeable at zero coupling, and escrow's satisfies audit's
	// as declared.
	log := audit.NewMemory(audit.MemoryConfig{Clock: escrow.NewFixedClock(testNow())})
	tr, err := escrow.NewTrail(log)
	if err != nil {
		t.Fatalf("NewTrail: %v", err)
	}
	ctx := context.Background()

	seal := mustSealID(t)
	want := 0
	for _, kind := range escrow.AttemptKinds() {
		for _, outcome := range escrow.AttemptOutcomes() {
			attempt := testAttempt(t, seal, kind, outcome)
			if err := tr.Record(ctx, attempt); err != nil {
				t.Fatalf("Record(%s/%s): %v", kind, outcome, err)
			}
			want++
		}
	}

	entries := readAll(t, log)
	if len(entries) != want {
		t.Fatalf("recorded %d attempts, the chain holds %d", want, len(entries))
	}

	// The chain verifies, which is the whole reason this module depends on
	// audit rather than appending to a table of its own.
	if _, err := audit.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
		t.Fatalf("the trail does not verify: %v", err)
	}

	seen := make(map[string]int, want)
	for _, e := range entries {
		if e.Event.Subject.Kind != "seal" {
			t.Fatalf("an entry's subject kind is %q, want \"seal\"", e.Event.Subject.Kind)
		}
		if e.Event.Subject.ID != seal.String() {
			t.Fatalf("an entry's subject id is %q, want the seal id", e.Event.Subject.ID)
		}
		if !strings.HasPrefix(string(e.Event.Action), "escrow.") {
			t.Fatalf("an entry's action is %q, want it namespaced under escrow.", e.Event.Action)
		}
		seen[string(e.Event.Action)+"/"+string(e.Event.Outcome)]++
	}
	if len(seen) != want {
		t.Fatalf("%d distinct action/outcome pairs reached the chain, want %d", len(seen), want)
	}

	// The failures and the refusals are there, which is the point.
	for _, outcome := range []domain.AttemptOutcome{domain.AttemptRefused, domain.AttemptFailed} {
		found := false
		for key := range seen {
			if strings.HasSuffix(key, "/"+string(outcome)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no %s attempt reached the chain: the failed ones are the interesting signal", outcome)
		}
	}
}

// TestRecordedDetailIsCanonicalAndCarriesTheGeneration covers the two things
// about the detail payload that matter.
//
// The generation, because a trail read after a re-seal cannot otherwise tell
// which arrangement an attempt was made against — which is most of what the
// trail is read for. And byte-stability, because audit's entry digest commits
// to the exact submitted bytes: a detail encoded through a Go map would make
// two processes recording the same attempt produce two different entries.
func TestRecordedDetailIsCanonicalAndCarriesTheGeneration(t *testing.T) {
	t.Parallel()

	log := audit.NewMemory(audit.MemoryConfig{Clock: escrow.NewFixedClock(testNow())})
	tr, err := escrow.NewTrail(log)
	if err != nil {
		t.Fatalf("NewTrail: %v", err)
	}
	ctx := context.Background()

	seal := mustSealID(t)
	attempt := testAttempt(t, seal, domain.AttemptNotification, domain.AttemptFailed)
	attempt.Generation = 7
	attempt.Reason = "the gateway refused the message"

	// The same attempt twice: the chain's two entries differ in their id,
	// sequence and link, and must not differ in their detail bytes.
	for range 2 {
		if err := tr.Record(ctx, attempt); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	entries := readAll(t, log)
	if len(entries) != 2 {
		t.Fatalf("the chain holds %d entries, want 2", len(entries))
	}
	if string(entries[0].Event.Detail) != string(entries[1].Event.Detail) {
		t.Fatalf("two recordings of one attempt produced different detail bytes:\n%s\n%s",
			entries[0].Event.Detail, entries[1].Event.Detail)
	}

	var detail struct {
		Generation uint32 `json:"generation"`
		ObservedAt string `json:"observed_at"`
		Channel    string `json:"channel"`
		Ceremony   string `json:"ceremony"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(entries[0].Event.Detail, &detail); err != nil {
		t.Fatalf("the detail payload is not the JSON this module wrote: %v", err)
	}
	if detail.Generation != 7 {
		t.Fatalf("detail.generation = %d, want 7", detail.Generation)
	}
	if detail.Channel != "sms" {
		t.Fatalf("detail.channel = %q, want \"sms\"", detail.Channel)
	}
	if detail.Reason != attempt.Reason {
		t.Fatalf("detail.reason = %q, want %q", detail.Reason, attempt.Reason)
	}
	// The instant this module observed, as distinct from the instant audit
	// recorded. The two diverge when an attempt is recorded after a retry, and
	// the trail must show both.
	if detail.ObservedAt != attempt.At.Format("2006-01-02T15:04:05.000000Z07:00") {
		t.Fatalf("detail.observed_at = %q, want the attempt's own instant", detail.ObservedAt)
	}
	if entries[0].Event.Timestamp.IsZero() {
		t.Fatal("the audit entry has no timestamp of its own")
	}

	// A ceremony id appears only when the attempt belongs to one: a proof of
	// life belongs to none, and an empty string in the record would read as a
	// ceremony nobody can find.
	if detail.Ceremony != "" {
		t.Fatalf("detail.ceremony = %q for an attempt that names none", detail.Ceremony)
	}
}

func TestRecordRefusesAMalformedAttempt(t *testing.T) {
	t.Parallel()

	log := audit.NewMemory(audit.MemoryConfig{})
	tr, err := escrow.NewTrail(log)
	if err != nil {
		t.Fatalf("NewTrail: %v", err)
	}
	ctx := context.Background()
	seal := mustSealID(t)

	cases := map[string]func(a *domain.Attempt){
		"no outcome":                     func(a *domain.Attempt) { a.Outcome = "" },
		"an unknown kind":                func(a *domain.Attempt) { a.Kind = "pondered" },
		"no actor":                       func(a *domain.Attempt) { a.Actor = domain.CustodianID{} },
		"no seal":                        func(a *domain.Attempt) { a.Seal = domain.SealID{} },
		"generation zero":                func(a *domain.Attempt) { a.Generation = 0 },
		"a notification with no channel": func(a *domain.Attempt) { a.Channel = "" },
		"a non-canonical instant":        func(a *domain.Attempt) { a.At = a.At.Add(time.Nanosecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			attempt := testAttempt(t, seal, domain.AttemptNotification, domain.AttemptFailed)
			mutate(&attempt)
			if err := tr.Record(ctx, attempt); !errors.Is(err, escrow.ErrInvalidArgument) {
				t.Fatalf("Record error = %v, want ErrInvalidArgument", err)
			}
		})
	}

	// A rejected attempt leaves the chain exactly as it was.
	head, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if !head.IsZero() {
		t.Fatalf("the chain moved to %s on rejected attempts", head)
	}
}

// TestNewTrailRefusesANilLog: a trail that silently recorded nothing would be
// worse than no trail, because an empty trail would read as nothing having
// been attempted.
func TestNewTrailRefusesANilLog(t *testing.T) {
	t.Parallel()

	tr, err := escrow.NewTrail(nil)
	if !errors.Is(err, escrow.ErrInvalidConfig) {
		t.Fatalf("NewTrail(nil) error = %v, want ErrInvalidConfig", err)
	}
	if tr != nil {
		t.Fatal("NewTrail returned a trail alongside an error")
	}
}

// ---- helpers ----

func testNow() time.Time {
	return escrow.CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))
}

func mustSealID(t *testing.T) escrow.SealID {
	t.Helper()

	id, err := escrow.NewSealID(escrow.NewFixedClock(testNow()))
	if err != nil {
		t.Fatalf("NewSealID: %v", err)
	}
	return id
}

func testAttempt(t *testing.T, seal escrow.SealID, kind domain.AttemptKind, outcome domain.AttemptOutcome) domain.Attempt {
	t.Helper()

	actor, err := escrow.ParseCustodianID("deployment")
	if err != nil {
		t.Fatalf("ParseCustodianID: %v", err)
	}
	tenant, err := escrow.ParseTenantID("tenant-1")
	if err != nil {
		t.Fatalf("ParseTenantID: %v", err)
	}

	attempt := domain.Attempt{
		Tenant:     tenant,
		Seal:       seal,
		Generation: domain.FirstGeneration,
		Kind:       kind,
		Outcome:    outcome,
		Actor:      actor,
		At:         testNow(),
	}
	switch kind {
	case domain.AttemptProofOfLife, domain.AttemptNotification:
		attempt.Channel = "sms"
	case domain.AttemptShareRelease, domain.AttemptUnseal:
		attempt.Channel = ""
	}
	return attempt
}

func readAll(t *testing.T, log audit.Log) []audit.Entry {
	t.Helper()

	entries, err := log.Entries(context.Background(), 0, 1000)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	return entries
}
