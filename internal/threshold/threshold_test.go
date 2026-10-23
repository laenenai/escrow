package threshold

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	shamir "github.com/mvrahden/go-shamir"

	"github.com/laenenai/escrow/internal/domain"
)

// The first three tests are **dependency acceptance tests**: they assert
// properties of github.com/mvrahden/go-shamir rather than of this package,
// and they exist because the spike that chose that dependency
// (docs/superpowers/spikes/2026-10-23-shamir-library) chose a small,
// single-maintainer module over a heavier institutionally-maintained one on
// the explicit condition that its maintenance risk be converted into tests
// here. An upgrade that changed the finite field, the share layout, or the
// coefficient distribution fails in this file instead of in a consumer's
// deployment.

// TestTSSKnownAnswerVector is the independent known-answer test for the
// finite field and the share layout, from draft-mcgrew-tss-03 §9
// (https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03), which
// specifies Threshold Secret Sharing over GF(256) modulo the AES polynomial
// 0x11B.
//
// It is worth more than a round-trip test because it pins two things at
// once: the field (a different irreducible polynomial gives a different
// answer — the one candidate that uses 0x11D returns 7667737602 here) and
// the share layout (the value followed by the one-byte x-coordinate). Both
// are assumptions this package makes in split and Reconstruct.
//
// The draft is an expired individual IETF submission and never became an
// RFC. That is its one weakness, and it is still the only published
// known-answer test for bare GF(256) Shamir that exists; Botan's TSS, tss-rb
// and OASIS SAM-TSS v1.0 all validate against it. SLIP-0039's 45 official
// vectors use the same field but only reach it through PBKDF2, a Feistel
// construction and an RS1024 checksum, so they cannot be fed to a bare
// Combine.
func TestTSSKnownAnswerVector(t *testing.T) {
	t.Parallel()

	secret := mustHex(t, "7465737400") // "test\0"
	parts := [][]byte{
		append(mustHex(t, "b9fa07e185"), 0x01),
		append(mustHex(t, "f5409b4511"), 0x02),
	}

	got, err := shamir.Combine(parts)
	if err != nil {
		t.Fatalf("Combine on the TSS vector: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("the TSS vector reconstructed to %x, want %x.\n"+
			"the dependency's finite field or share layout has changed: see the spike note under "+
			"docs/superpowers/spikes/2026-10-23-shamir-library", got, secret)
	}
}

// TestShareLayoutIsMaterialThenIndex pins the layout split and Reconstruct
// take apart: a share is the secret's length plus exactly one byte, and that
// byte is the x-coordinate, at the end.
//
// It also records the fact that the x-coordinates are **not** 1..N. The
// splitter chooses them, and that is why domain.ShareIndex is documented as
// an x-coordinate and why domain.Seal.Validate requires the custodians'
// indices to be distinct rather than to cover 1..Total.
func TestShareLayoutIsMaterialThenIndex(t *testing.T) {
	t.Parallel()

	if shamir.ShareOverhead != 1 {
		t.Fatalf("ShareOverhead = %d, want 1: split and Reconstruct assume one trailing index byte", shamir.ShareOverhead)
	}

	secret := bytes.Repeat([]byte{0xAB}, domain.KeySize)
	secret[0] = 0x01
	parts, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	seen := make(map[byte]struct{}, len(parts))
	for i, part := range parts {
		if len(part) != domain.KeySize+1 {
			t.Fatalf("share %d is %d bytes, want %d", i, len(part), domain.KeySize+1)
		}
		x := part[len(part)-1]
		if x == 0 {
			t.Fatalf("share %d has x-coordinate 0, which is the secret itself", i)
		}
		if _, dup := seen[x]; dup {
			t.Fatalf("two shares share x-coordinate %d", x)
		}
		seen[x] = struct{}{}
	}
}

// TestSharesAreUniformlyDistributed is the measurement that information-
// theoretic secrecy still holds: with k−1 shares of a one-byte secret, the
// share's value must be uniform over 0..255, so it equals the secret about
// one time in 256.
//
// This is the test that disqualified an otherwise excellent candidate. Two
// published implementations force the polynomial's leading coefficient to be
// non-zero — "or else it's a lower degree polynomial" — which means the
// share at any x can never equal the secret, and one candidate value per
// secret byte is therefore excludable by a holder of k−1 shares. The leak is
// small (~0.18 bits over a 32-byte key); giving up the theorem in the module
// whose proposition is "k−1 shares reveal nothing" is not.
//
// The assertion is deliberately one-sided and loose. The failure it is built
// to catch is categorical — exactly zero hits, not a skewed count — so the
// band is wide enough that a legitimate implementation cannot flake, and no
// band at all would still catch the thing that matters.
func TestSharesAreUniformlyDistributed(t *testing.T) {
	t.Parallel()

	const (
		trials = 60000
		secret = byte(0x42)
	)

	hits := 0
	for range trials {
		parts, err := shamir.Split([]byte{secret}, 2, 2)
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		// One sample per split, from one share. Samples within a split are
		// points on the same polynomial and are perfectly correlated when
		// the slope is zero, so counting several of them per trial would
		// destroy the test's power rather than multiply it.
		if parts[0][0] == secret {
			hits++
		}
	}

	expected := float64(trials) / 256
	if hits == 0 {
		t.Fatalf("in %d trials a k-1 share never equalled the secret, expected about %.0f.\n"+
			"the dependency forces a non-zero leading coefficient, which forfeits "+
			"information-theoretic secrecy: see the spike note under "+
			"docs/superpowers/spikes/2026-10-23-shamir-library", trials, expected)
	}
	if float64(hits) < expected/3 || float64(hits) > expected*3 {
		t.Fatalf("in %d trials a k-1 share equalled the secret %d times, expected about %.0f: "+
			"the share distribution is not uniform", trials, hits, expected)
	}
}

// TestBelowThresholdInterpolatesSilently records the hazard this package
// exists to close, as a test rather than as a comment: the dependency does
// not refuse a below-threshold set, it interpolates whatever it was given
// and returns a wrong secret with a nil error.
//
// If this test ever fails because the dependency started returning an error,
// nothing here becomes unnecessary — a *fabricated* share is indistinguishable
// from a real one by construction, so the commitment is still the only real
// check. It would only mean one of the two ways to get a wrong key had been
// closed by somebody else.
func TestBelowThresholdInterpolatesSilently(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{0xAB}, domain.KeySize)
	secret[0] = 0x01
	parts, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	got, err := shamir.Combine(parts[:2])
	if err != nil {
		t.Logf("the dependency now rejects a below-threshold set (%v); the commitment is still required", err)
		return
	}
	if bytes.Equal(got, secret) {
		t.Fatal("two of three shares reconstructed the secret: the threshold is not being enforced at all")
	}
	t.Logf("as expected: a below-threshold set interpolated a wrong value with no error")
}

// TestCreateProducesASealEveryQuorumCanOpen is the happy path, asserted over
// every quorum rather than over one: any Required of the Total shares must
// reconstruct the key, and the key must verify against the seal's
// commitment.
func TestCreateProducesASealEveryQuorumCanOpen(t *testing.T) {
	t.Parallel()

	seal, key, shares := mustCreate(t, 3, 5)
	defer key.Destroy()

	if seal.Generation != domain.FirstGeneration {
		t.Fatalf("a created seal is at %s, want %s", seal.Generation, domain.FirstGeneration)
	}
	if seal.Commitment.IsZero() {
		t.Fatal("a created seal carries no commitment")
	}
	if got := domain.CommitKey(seal.ID, seal.Generation, key); !seal.Commitment.Equal(got) {
		t.Fatal("the seal's commitment is not the commitment of the key it returned")
	}
	if len(shares) != seal.Threshold.Total {
		t.Fatalf("cut %d shares for a %s threshold", len(shares), seal.Threshold)
	}

	for _, quorum := range combinations(len(shares), seal.Threshold.Required) {
		subset := make([]domain.Share, 0, len(quorum))
		for _, i := range quorum {
			subset = append(subset, shares[i])
		}
		got, err := Reconstruct(seal, subset)
		if err != nil {
			t.Fatalf("Reconstruct with shares %v: %v", quorum, err)
		}
		if !got.Equal(key) {
			t.Fatalf("Reconstruct with shares %v returned a different key", quorum)
		}
		got.Destroy()
	}
}

// TestReconstructRefusesRatherThanReturningAWrongKey is the central test of
// the module: each of these would, with plain Shamir and no commitment,
// return a wrong key and a nil error.
func TestReconstructRefusesRatherThanReturningAWrongKey(t *testing.T) {
	t.Parallel()

	sealA, keyA, sharesA := mustCreate(t, 3, 5)
	defer keyA.Destroy()
	_, keyB, sharesB := mustCreate(t, 3, 5)
	defer keyB.Destroy()

	tests := map[string]struct {
		shares []domain.Share
		want   error
	}{
		// A corrupted share: one byte of material flipped. The binding is
		// intact, so nothing but the commitment can catch it.
		"corrupted share": {
			shares: append([]domain.Share{corrupt(t, sharesA[0])}, sharesA[1], sharesA[2]),
			want:   domain.ErrReconstructionUnverified,
		},
		// A share from another seal, presented as itself. Caught cheaply, by
		// the binding, before any arithmetic.
		"share from another seal, binding intact": {
			shares: append([]domain.Share{sharesB[0]}, sharesA[1], sharesA[2]),
			want:   domain.ErrForeignShare,
		},
		// The same share with its binding rewritten to claim this seal. This
		// is the one that matters: the binding is unkeyed, so a determined
		// holder can forge it, and only the commitment is a guarantee.
		"share from another seal, binding rewritten": {
			shares: append([]domain.Share{rebind(t, sharesB[0], sealA.ID, sealA.Generation)}, sharesA[1], sharesA[2]),
			want:   domain.ErrReconstructionUnverified,
		},
		// A duplicate: one custodian presenting one share three times must
		// not satisfy a 3-of-5 threshold.
		"duplicate share": {
			shares: []domain.Share{sharesA[0], sharesA[0], sharesA[0]},
			want:   domain.ErrDuplicateShare,
		},
		"duplicate index with different material": {
			shares: []domain.Share{sharesA[0], corrupt(t, sharesA[0]), sharesA[1]},
			want:   domain.ErrDuplicateShare,
		},
		// Below the threshold. Refused before interpolating, because the
		// dependency does not refuse it — see
		// TestBelowThresholdInterpolatesSilently.
		"too few shares": {
			shares: sharesA[:2],
			want:   domain.ErrInsufficientShares,
		},
		"no shares at all": {
			shares: nil,
			want:   domain.ErrInsufficientShares,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := Reconstruct(sealA, tc.shares)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Reconstruct error = %v, want %v", err, tc.want)
			}
			if !got.IsZero() {
				got.Destroy()
				t.Fatal("Reconstruct returned key material alongside an error")
			}
		})
	}
}

// TestRotateMakesOldSharesFail is CHARTER.md's fourth safety property, and
// the assertion is deliberately that the old shares **fail**, not that they
// are marked stale.
//
// Both halves are tested, because only the second one is a guarantee:
//
//   - A full old quorum, presented as itself, is refused by the binding.
//   - The same quorum with every binding rewritten to claim the new
//     generation is refused by the commitment. A holder who kept a share and
//     is willing to edit its envelope gets no further than one who is not.
//
// And the inverse: the new shares must open the new seal, so a rotation is a
// rotation and not a bricking.
func TestRotateMakesOldSharesFail(t *testing.T) {
	t.Parallel()

	seal, oldKey, oldShares := mustCreate(t, 3, 5)
	defer oldKey.Destroy()

	rotated, newKey, newShares, err := Rotate(seal, PlanFrom(seal), domain.NewFixedClock(testNow().Add(time.Hour)))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	defer newKey.Destroy()

	if rotated.Generation != seal.Generation.Next() {
		t.Fatalf("rotated seal is at %s, want %s", rotated.Generation, seal.Generation.Next())
	}
	if newKey.Equal(oldKey) {
		t.Fatal("Rotate returned the same key: a re-seal that does not rotate the key leaves every distributed share able to open it")
	}
	if rotated.Commitment.Equal(seal.Commitment) {
		t.Fatal("Rotate kept the old commitment")
	}
	if !rotated.CreatedAt.Equal(seal.CreatedAt) {
		t.Fatal("Rotate changed the seal's creation instant")
	}

	t.Run("old shares as themselves", func(t *testing.T) {
		got, err := Reconstruct(rotated, oldShares[:3])
		if !errors.Is(err, domain.ErrForeignShare) {
			t.Fatalf("error = %v, want ErrForeignShare", err)
		}
		if !got.IsZero() {
			got.Destroy()
			t.Fatal("key material returned alongside an error")
		}
	})

	t.Run("old shares with their binding rewritten to the new generation", func(t *testing.T) {
		forged := make([]domain.Share, 0, 3)
		for _, s := range oldShares[:3] {
			forged = append(forged, rebind(t, s, rotated.ID, rotated.Generation))
		}
		got, err := Reconstruct(rotated, forged)
		if !errors.Is(err, domain.ErrReconstructionUnverified) {
			t.Fatalf("error = %v, want ErrReconstructionUnverified.\n"+
				"a re-seal that only *labels* old shares stale is not CHARTER.md's property 4: "+
				"they must fail", err)
		}
		if !got.IsZero() {
			got.Destroy()
			t.Fatal("key material returned alongside an error")
		}
	})

	t.Run("old shares still open the old seal", func(t *testing.T) {
		// Not a loophole: the old generation's record is superseded in the
		// store, and this asserts that the failure above is about the
		// generation rather than about the shares having been damaged.
		got, err := Reconstruct(seal, oldShares[:3])
		if err != nil {
			t.Fatalf("Reconstruct against the superseded seal record: %v", err)
		}
		if !got.Equal(oldKey) {
			t.Fatal("the old shares no longer reconstruct the old key")
		}
		got.Destroy()
	})

	t.Run("new shares open the new seal", func(t *testing.T) {
		got, err := Reconstruct(rotated, newShares[:3])
		if err != nil {
			t.Fatalf("Reconstruct with the new shares: %v", err)
		}
		if !got.Equal(newKey) {
			t.Fatal("the new shares do not reconstruct the new key")
		}
		got.Destroy()
	})
}

// TestSystemSharesAreNeverSufficient is CHARTER.md's first safety property
// over **every threshold the API accepts**, not over a sample of them.
//
// The deployment holds at most domain.MaxSystemHeldShares shares. The claim
// is that this is strictly below the required count for every (M, N) that
// domain.Threshold.Validate permits — so the claim is checked by enumerating
// that whole set and asserting it, and by asserting that the thresholds
// outside it are the ones that are refused.
//
// The second half then does it operationally for the smallest and most
// dangerous case, a 2-of-2 seal: cut it, present only the share the system
// would hold, and require a refusal.
func TestSystemSharesAreNeverSufficient(t *testing.T) {
	t.Parallel()

	t.Run("over every accepted threshold", func(t *testing.T) {
		t.Parallel()

		accepted := 0
		for total := 1; total <= domain.MaxShares+1; total++ {
			for required := 0; required <= total; required++ {
				th := domain.Threshold{Required: required, Total: total}
				if err := th.Validate(); err != nil {
					if required >= domain.MinThreshold && required <= total && total <= domain.MaxShares {
						t.Fatalf("%s was refused but is within the documented bounds: %v", th, err)
					}
					continue
				}
				accepted++
				if domain.MaxSystemHeldShares >= th.Required {
					t.Fatalf("%s is accepted, but the deployment's %d share(s) would reach its required %d",
						th, domain.MaxSystemHeldShares, th.Required)
				}
			}
		}
		if accepted == 0 {
			t.Fatal("no threshold was accepted at all: the enumeration is wrong, not the invariant")
		}
		t.Logf("%d thresholds accepted, every one of them requires more than the %d share the deployment may hold",
			accepted, domain.MaxSystemHeldShares)
	})

	t.Run("the deployment's own share does not open a 2-of-2 seal", func(t *testing.T) {
		t.Parallel()

		seal, key, shares := mustCreate(t, 2, 2)
		defer key.Destroy()

		system, ok := seal.SystemCustodian()
		if !ok {
			t.Fatal("the test plan named a system custodian but the seal has none")
		}
		var held domain.Share
		for _, s := range shares {
			if s.Index() == system.Index {
				held = s
			}
		}
		if held.IsZero() {
			t.Fatal("no share was cut at the system custodian's index")
		}

		got, err := Reconstruct(seal, []domain.Share{held})
		if !errors.Is(err, domain.ErrInsufficientShares) {
			t.Fatalf("error = %v, want ErrInsufficientShares", err)
		}
		if !got.IsZero() {
			got.Destroy()
			t.Fatal("the deployment reconstructed a key from its own single share")
		}
	})
}

// TestReleasePathErrorsDoNotLeakMaterial pushes real key material and real
// share material through every error path in this package and requires that
// none of the resulting strings contains either — raw, hex-encoded,
// base64-encoded, or as a length in decimal.
//
// The release and unseal paths are the ones that hold both at once, and an
// error string is the value most likely to end up in a log file somebody
// else can read.
func TestReleasePathErrorsDoNotLeakMaterial(t *testing.T) {
	t.Parallel()

	sealA, keyA, sharesA := mustCreate(t, 3, 5)
	defer keyA.Destroy()
	sealB, keyB, sharesB := mustCreate(t, 3, 5)
	defer keyB.Destroy()

	// Cloned, not aliased. Destroy zeroizes the one backing array every copy
	// of a key shares, so a deferred Destroy in this function would leave the
	// assertions below comparing error strings against 32 zero bytes and
	// passing for the wrong reason.
	secrets := [][]byte{bytes.Clone(keyA.Bytes()), bytes.Clone(keyB.Bytes())}
	for _, s := range sharesA {
		secrets = append(secrets, bytes.Clone(s.Material()))
	}
	for _, s := range sharesB {
		secrets = append(secrets, bytes.Clone(s.Material()))
	}

	attempts := map[string][]domain.Share{
		"corrupted":        {corrupt(t, sharesA[0]), sharesA[1], sharesA[2]},
		"foreign":          {sharesB[0], sharesA[1], sharesA[2]},
		"rebound":          {rebind(t, sharesB[0], sealA.ID, sealA.Generation), sharesA[1], sharesA[2]},
		"duplicate":        {sharesA[0], sharesA[0], sharesA[0]},
		"insufficient":     sharesA[:1],
		"all five foreign": sharesB,
	}

	public := publicTokens([]domain.Seal{sealA, sealB}, sharesA, sharesB)

	for name, shares := range attempts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Reconstruct(sealA, shares)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			assertNoSecret(t, err.Error(), secrets, public...)
		})
	}

	t.Run("split of invalid key material", func(t *testing.T) {
		t.Parallel()

		_, err := split(sealA.ID, sealA.Generation, sealA.Threshold, domain.SealedKey{})
		if err == nil {
			t.Fatal("expected a refusal")
		}
		assertNoSecret(t, err.Error(), secrets, public...)
	})
}

func TestPlanValidate(t *testing.T) {
	t.Parallel()

	good := testPlan(t, 3, 5)
	tests := map[string]struct {
		mutate func(p *Plan)
		want   error
	}{
		"below the minimum threshold": {
			mutate: func(p *Plan) { p.Threshold = domain.Threshold{Required: 1, Total: 5} },
			want:   domain.ErrInvalidThreshold,
		},
		"more required than exist": {
			mutate: func(p *Plan) { p.Threshold = domain.Threshold{Required: 6, Total: 5} },
			want:   domain.ErrInvalidThreshold,
		},
		"too many shares for the field": {
			mutate: func(p *Plan) { p.Threshold = domain.Threshold{Required: 2, Total: domain.MaxShares + 1} },
			want:   domain.ErrInvalidThreshold,
		},
		"wrong number of holders": {
			mutate: func(p *Plan) { p.Holders = p.Holders[:4] },
			want:   domain.ErrInvalidArgument,
		},
		"a holder named twice": {
			mutate: func(p *Plan) { p.Holders[1] = p.Holders[0] },
			want:   domain.ErrInvalidArgument,
		},
		"an empty holder": {
			mutate: func(p *Plan) { p.Holders[2] = domain.CustodianID{} },
			want:   domain.ErrInvalidArgument,
		},
		"a system custodian that holds nothing": {
			mutate: func(p *Plan) { p.System = mustCustodian(t, "stranger") },
			want:   domain.ErrInvalidArgument,
		},
		"a schedule with one channel": {
			mutate: func(p *Plan) {
				p.Liveness.Escalations = []domain.Escalation{{After: 0, Channel: "email"}, {After: time.Hour, Channel: "email"}}
			},
			want: domain.ErrInvalidSchedule,
		},
		"a schedule with no grace period": {
			mutate: func(p *Plan) { p.Liveness.Grace = 0 },
			want:   domain.ErrInvalidSchedule,
		},
	}

	if err := good.Validate(); err != nil {
		t.Fatalf("the baseline plan does not validate: %v", err)
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := testPlan(t, 3, 5)
			tc.mutate(&p)
			if err := p.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReconstructIsIndifferentToShareOrder: a ceremony collects shares in
// whatever order the custodians arrive, and the order must not be part of
// the arrangement nobody wrote down.
func TestReconstructIsIndifferentToShareOrder(t *testing.T) {
	t.Parallel()

	seal, key, shares := mustCreate(t, 3, 3)
	defer key.Destroy()

	orders := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}}
	for _, order := range orders {
		subset := make([]domain.Share, 0, 3)
		for _, i := range order {
			subset = append(subset, shares[i])
		}
		got, err := Reconstruct(seal, subset)
		if err != nil {
			t.Fatalf("Reconstruct in order %v: %v", order, err)
		}
		if !got.Equal(key) {
			t.Fatalf("Reconstruct in order %v returned a different key", order)
		}
		got.Destroy()
	}
}

// TestCreateAcceptsASealTheDeploymentHoldsNoShareOf: a plan with no system
// custodian is a stronger arrangement, not an invalid one, and must be
// accepted — the deployment then cannot contribute at all.
func TestCreateAcceptsASealTheDeploymentHoldsNoShareOf(t *testing.T) {
	t.Parallel()

	plan := testPlan(t, 2, 3)
	plan.System = domain.CustodianID{}

	seal, key, shares := mustCreateWith(t, plan)
	defer key.Destroy()

	if _, ok := seal.SystemCustodian(); ok {
		t.Fatal("the seal named a system custodian for a plan that named none")
	}
	if seal.SystemHeldShares() != 0 {
		t.Fatalf("the deployment holds %d shares of a seal it should hold none of", seal.SystemHeldShares())
	}
	if seal.IsSystemSufficient() {
		t.Fatal("a seal the deployment holds no share of reports the deployment as sufficient")
	}
	got, err := Reconstruct(seal, shares[:2])
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	got.Destroy()
}

// ---- helpers ----

// testNow is the fixed instant every test in this file counts from, already
// canonical so that nothing has to remember to truncate it.
func testNow() time.Time {
	return domain.CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))
}

// testSchedule is a liveness schedule that validates: two independent
// channels, a strictly advancing ladder, and a grace period.
func testSchedule() domain.LivenessSchedule {
	return domain.LivenessSchedule{
		Since:   testNow(),
		CheckIn: 30 * 24 * time.Hour,
		Escalations: []domain.Escalation{
			{After: 0, Channel: "email"},
			{After: 7 * 24 * time.Hour, Channel: "sms"},
			{After: 14 * 24 * time.Hour, Channel: "postal"},
		},
		Grace: 14 * 24 * time.Hour,
	}
}

func testPlan(t *testing.T, required, total int) Plan {
	t.Helper()

	holders := make([]domain.CustodianID, 0, total)
	for i := range total {
		holders = append(holders, mustCustodian(t, "custodian-"+strconv.Itoa(i)))
	}
	return Plan{
		Threshold: domain.Threshold{Required: required, Total: total},
		Holders:   holders,
		System:    holders[0],
		Liveness:  testSchedule(),
	}
}

func mustCreate(t *testing.T, required, total int) (domain.Seal, domain.SealedKey, []domain.Share) {
	t.Helper()
	return mustCreateWith(t, testPlan(t, required, total))
}

func mustCreateWith(t *testing.T, plan Plan) (domain.Seal, domain.SealedKey, []domain.Share) {
	t.Helper()

	seal, key, shares, err := Create(mustTenant(t), plan, domain.NewFixedClock(testNow()))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return seal, key, shares
}

func mustTenant(t *testing.T) domain.TenantID {
	t.Helper()

	id, err := domain.ParseTenantID("tenant-1")
	if err != nil {
		t.Fatalf("ParseTenantID: %v", err)
	}
	return id
}

func mustCustodian(t *testing.T, s string) domain.CustodianID {
	t.Helper()

	id, err := domain.ParseCustodianID(s)
	if err != nil {
		t.Fatalf("ParseCustodianID(%q): %v", s, err)
	}
	return id
}

// corrupt returns a copy of s with one byte of its material flipped: a
// custodian whose share was mistranscribed, or who altered it. The binding
// is untouched, so nothing but the commitment can catch it.
func corrupt(t *testing.T, s domain.Share) domain.Share {
	t.Helper()

	material := bytes.Clone(s.Material())
	material[0] ^= 0xFF
	out, err := domain.NewShare(s.Seal(), s.Generation(), s.Index(), material)
	if err != nil {
		t.Fatalf("build a corrupted share: %v", err)
	}
	return out
}

// rebind returns a copy of s claiming a different seal and generation: the
// forgery a holder of a superseded share would attempt, since the binding is
// unkeyed and an exported share's checksum can be recomputed.
func rebind(t *testing.T, s domain.Share, seal domain.SealID, generation domain.Generation) domain.Share {
	t.Helper()

	out, err := domain.NewShare(seal, generation, s.Index(), s.Material())
	if err != nil {
		t.Fatalf("rebind a share: %v", err)
	}
	return out
}

// assertNoSecret fails if text contains any of the secrets, in any of the
// encodings a careless interpolation would produce, or any of their lengths
// in decimal.
//
// The public identifiers an error is *allowed* to name — the seal ids, the
// generations, the share indices — are redacted out of the text before the
// length is searched for, and that is not a loophole: it is what makes the
// length assertion mean something. A minted seal id is 32 random hex
// characters, so roughly one error in eight contains the substring "32"
// somewhere inside an identifier the caller already holds, and this test
// failed exactly that way before the redaction existed. Searching the
// *remainder* asserts the thing actually wanted: that an error says nothing
// beyond the identifiers its caller passed in.
func assertNoSecret(t *testing.T, text string, secrets [][]byte, public ...string) {
	t.Helper()

	remainder := text
	for _, token := range public {
		if token == "" {
			continue
		}
		remainder = strings.ReplaceAll(remainder, token, "<public>")
	}

	for i, secret := range secrets {
		for label, encoded := range encodings(secret) {
			if strings.Contains(text, encoded) {
				t.Fatalf("secret %d leaked as %s into: %q", i, label, text)
			}
		}
		if n := strconv.Itoa(len(secret)); strings.Contains(remainder, n) {
			t.Fatalf("the length of secret %d (%s) leaked into: %q\n(with the public identifiers redacted: %q)",
				i, n, text, remainder)
		}
	}
}

// publicTokens lists the identifiers the errors in this file are allowed to
// name: the seals, their generations and their share indices. See
// assertNoSecret.
func publicTokens(seals []domain.Seal, shares ...[]domain.Share) []string {
	var out []string
	for _, seal := range seals {
		out = append(out, seal.ID.String(), seal.Generation.String(), seal.Threshold.String(),
			strconv.Itoa(seal.Threshold.Required), strconv.Itoa(seal.Threshold.Total))
	}
	for _, set := range shares {
		for _, share := range set {
			out = append(out, strconv.Itoa(int(share.Index())), share.Generation().String())
		}
	}
	return out
}

// encodings returns the renderings of b that a leak would plausibly take.
func encodings(b []byte) map[string]string {
	return map[string]string{
		"raw bytes":       string(b),
		"lowercase hex":   hex.EncodeToString(b),
		"uppercase hex":   strings.ToUpper(hex.EncodeToString(b)),
		"standard base64": base64.StdEncoding.EncodeToString(b),
		"url base64":      base64.URLEncoding.EncodeToString(b),
		"go byte slice":   fmt.Sprintf("%v", b),
	}
}

// combinations returns every k-sized subset of the indices 0..n-1, so a
// quorum assertion covers all of them rather than one.
func combinations(n, k int) [][]int {
	var out [][]int
	idx := make([]int, k)
	var rec func(start, depth int)
	rec = func(start, depth int) {
		if depth == k {
			out = append(out, append([]int(nil), idx...))
			return
		}
		for i := start; i < n; i++ {
			idx[depth] = i
			rec(i+1, depth+1)
		}
	}
	rec(0, 0)
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}
