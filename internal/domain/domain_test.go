package domain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestKeyCommitmentTagIsPinned asserts the domain-separation tag literally.
//
// audit recorded why this test exists, and the lesson transfers exactly: a
// module-path correction there rewrote a cryptographic tag by textual
// substitution, and the failure presented as two digests that did not match
// rather than as a constant somebody had edited. A test on the literal makes
// the next such change report itself by name.
//
// The tag also contains no organisation or module path, so a repository
// rename cannot reach it in the first place.
func TestKeyCommitmentTagIsPinned(t *testing.T) {
	t.Parallel()

	if keyCommitmentTag != "escrow:key-commitment:v1" {
		t.Fatalf("keyCommitmentTag = %q: changing it invalidates every stored commitment, "+
			"which makes every existing seal unreconstructible — not merely unverifiable. "+
			"A change needs a new commitmentVersion, a new tag, and a new vector.", keyCommitmentTag)
	}
	if commitmentVersion != 0x01 {
		t.Fatalf("commitmentVersion = %#x, want 0x01", commitmentVersion)
	}
	if shareChecksumTag != "escrow:share-envelope:v1" {
		t.Fatalf("shareChecksumTag = %q", shareChecksumTag)
	}
	if shareEnvelopeVersion != 0x01 {
		t.Fatalf("shareEnvelopeVersion = %#x, want 0x01", shareEnvelopeVersion)
	}

	for _, tag := range []string{keyCommitmentTag, shareChecksumTag} {
		for _, forbidden := range []string{"laenenai", "laenen-ai", "github.com", "/"} {
			if strings.Contains(tag, forbidden) {
				t.Fatalf("tag %q contains %q: a repository rename must not be able to rewrite a cryptographic constant",
					tag, forbidden)
			}
		}
	}
}

// TestKeyCommitmentGoldenVector is the recorded vector for the commitment
// construction. A commitment is a persistence format — every seal ever
// written holds one, and the key it commits to exists nowhere else — so this
// test is what stops a refactor of CommitKey from quietly making every stored
// seal unreconstructible.
func TestKeyCommitmentGoldenVector(t *testing.T) {
	t.Parallel()

	seal, err := ParseSealID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("ParseSealID: %v", err)
	}
	material := make([]byte, KeySize)
	for i := range material {
		material[i] = byte(i)
	}
	// Byte 0 would otherwise be zero and the rest ascending, which is valid
	// material; nudged so the vector does not sit next to the all-zero
	// rejection case.
	material[0] = 0xFF
	key, err := SealedKeyFrom(material)
	if err != nil {
		t.Fatalf("SealedKeyFrom: %v", err)
	}
	defer key.Destroy()

	const want = "6fd200290201cd317e0efe0fd2081b5737964a80e5e1e5e8085a7d8f76acfe0d"
	if got := CommitKey(seal, FirstGeneration, key).String(); got != want {
		t.Fatalf("CommitKey = %s, want %s.\n"+
			"the commitment construction has changed, which invalidates every stored seal: "+
			"a change needs a new commitmentVersion, a new keyCommitmentTag and a new vector here", got, want)
	}
}

// TestKeyCommitmentBindsSealAndGeneration is why the seal id and the
// generation are inside the digest rather than merely stored beside it:
// without them a commitment could be lifted from one seal's record into
// another's and a key that verified under the first would verify under the
// second.
func TestKeyCommitmentBindsSealAndGeneration(t *testing.T) {
	t.Parallel()

	sealA, err := ParseSealID("00000000000000000000000000000001")
	if err != nil {
		t.Fatalf("ParseSealID: %v", err)
	}
	sealB, err := ParseSealID("00000000000000000000000000000002")
	if err != nil {
		t.Fatalf("ParseSealID: %v", err)
	}
	key, err := SealedKeyFrom(bytes.Repeat([]byte{0x11}, KeySize))
	if err != nil {
		t.Fatalf("SealedKeyFrom: %v", err)
	}
	defer key.Destroy()
	other, err := SealedKeyFrom(bytes.Repeat([]byte{0x12}, KeySize))
	if err != nil {
		t.Fatalf("SealedKeyFrom: %v", err)
	}
	defer other.Destroy()

	base := CommitKey(sealA, FirstGeneration, key)
	for name, got := range map[string]KeyCommitment{
		"a different seal":       CommitKey(sealB, FirstGeneration, key),
		"a different generation": CommitKey(sealA, FirstGeneration.Next(), key),
		"a different key":        CommitKey(sealA, FirstGeneration, other),
	} {
		if base.Equal(got) {
			t.Fatalf("%s produced the same commitment: the commitment does not bind it", name)
		}
	}
	if !base.Equal(CommitKey(sealA, FirstGeneration, key)) {
		t.Fatal("CommitKey is not deterministic")
	}
	if base.IsZero() {
		t.Fatal("a real commitment reports itself as the reserved zero value")
	}
}

func TestParseKeyCommitmentAndKeyCommitmentFrom(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0xAB}, 32)
	c, err := KeyCommitmentFrom(raw)
	if err != nil {
		t.Fatalf("KeyCommitmentFrom: %v", err)
	}
	if got := c.String(); got != hex.EncodeToString(raw) {
		t.Fatalf("String = %s", got)
	}
	back, err := ParseKeyCommitment(c.String())
	if err != nil {
		t.Fatalf("ParseKeyCommitment: %v", err)
	}
	if !back.Equal(c) {
		t.Fatal("a commitment did not round-trip through its hex form")
	}

	// Copied, not aliased: a commitment built from a database column must not
	// change when pgx reuses its buffer.
	clear(raw)
	if c.IsZero() {
		t.Fatal("KeyCommitmentFrom aliased the caller's slice")
	}

	for name, in := range map[string][]byte{"short": raw[:31], "long": append(raw, 0x00), "empty": nil} {
		if _, err := KeyCommitmentFrom(in); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("KeyCommitmentFrom(%s) error = %v, want ErrInvalidArgument", name, err)
		}
	}
	for name, in := range map[string]string{
		"too short": strings.Repeat("ab", 31),
		"uppercase": strings.ToUpper(strings.Repeat("ab", 32)),
		"not hex":   strings.Repeat("zz", 32),
		"empty":     "",
	} {
		if _, err := ParseKeyCommitment(in); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("ParseKeyCommitment(%s) error = %v, want ErrInvalidArgument", name, err)
		}
	}
}

// TestIdentifiersAreUnforgeable is the structural claim ids.go makes: the
// zero value names nothing, the only ways in are the mint and the parse, and
// a parse rejects anything that is not canonical.
func TestIdentifiersAreUnforgeable(t *testing.T) {
	t.Parallel()

	t.Run("the zero value names nothing", func(t *testing.T) {
		t.Parallel()

		if !(SealID{}).IsZero() || !(TenantID{}).IsZero() || !(CustodianID{}).IsZero() ||
			!(CeremonyID{}).IsZero() || !(ProofID{}).IsZero() {
			t.Fatal("a zero identifier does not report itself as naming nothing")
		}
		for name, s := range map[string]string{
			"seal":      (SealID{}).String(),
			"tenant":    (TenantID{}).String(),
			"custodian": (CustodianID{}).String(),
			"ceremony":  (CeremonyID{}).String(),
			"proof":     (ProofID{}).String(),
		} {
			if s != "" {
				t.Fatalf("a zero %s id renders as %q", name, s)
			}
		}
	})

	t.Run("minted ids are canonical, chronological and distinct", func(t *testing.T) {
		t.Parallel()

		clock := NewFixedClock(CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC)))
		seen := make(map[string]struct{}, 32)
		previous := ""
		for range 32 {
			id, err := NewSealID(clock)
			if err != nil {
				t.Fatalf("NewSealID: %v", err)
			}
			if _, err := ParseSealID(id.String()); err != nil {
				t.Fatalf("a minted id does not parse: %v", err)
			}
			seen[id.String()] = struct{}{}
			clock.Advance(time.Millisecond)
			if previous != "" && id.String() <= previous {
				t.Fatalf("ids minted a millisecond apart are not lexicographically ordered: %q then %q", previous, id)
			}
			previous = id.String()
		}
		if len(seen) != 32 {
			t.Fatalf("32 minted ids produced %d distinct values", len(seen))
		}

		// The other two minted kinds use the same machinery; assert they
		// parse rather than re-asserting the machinery.
		if id, err := NewCeremonyID(clock); err != nil || id.IsZero() {
			t.Fatalf("NewCeremonyID = %v, %v", id, err)
		}
		if id, err := NewProofID(clock); err != nil || id.IsZero() {
			t.Fatalf("NewProofID = %v, %v", id, err)
		}
	})

	t.Run("a minted id's parse rejects anything else", func(t *testing.T) {
		t.Parallel()

		for name, s := range map[string]string{
			"empty":       "",
			"too short":   strings.Repeat("a", 31),
			"too long":    strings.Repeat("a", 33),
			"uppercase":   strings.Repeat("A", 32),
			"not hex":     strings.Repeat("g", 32),
			"a ulid":      "01JATEST000000000000000000",
			"with spaces": strings.Repeat("a", 31) + " ",
		} {
			if _, err := ParseSealID(s); !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ParseSealID(%s) error = %v, want ErrMalformedID", name, err)
			}
			if _, err := ParseCeremonyID(s); !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ParseCeremonyID(%s) error = %v, want ErrMalformedID", name, err)
			}
			if _, err := ParseProofID(s); !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ParseProofID(%s) error = %v, want ErrMalformedID", name, err)
			}
		}
	})

	t.Run("a received id is validated for shape only", func(t *testing.T) {
		t.Parallel()

		for _, s := range []string{"t", "tenant-1", "01JATEST000000000000000000", "lawyer@example.com", "Ünïcode-name"} {
			if _, err := ParseTenantID(s); err != nil {
				t.Fatalf("ParseTenantID(%q): %v", s, err)
			}
			if _, err := ParseCustodianID(s); err != nil {
				t.Fatalf("ParseCustodianID(%q): %v", s, err)
			}
		}
		for name, s := range map[string]string{
			"empty":              "",
			"too long":           strings.Repeat("a", maxReceivedIDLen+1),
			"a path separator":   "a/b",
			"a backslash":        "a\\b",
			"a null byte":        "a\x00b",
			"a newline":          "a\nb",
			"a tab":              "a\tb",
			"leading whitespace": " a",
			"inner space":        "a b",
			"a relative path":    "..",
			"a single dot":       ".",
			"invalid utf-8":      "\xff\xfe",
		} {
			if _, err := ParseTenantID(s); !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ParseTenantID(%s) error = %v, want ErrMalformedID", name, err)
			}
			if err := ChannelID(s).Validate(); !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ChannelID(%s).Validate() error = %v, want ErrMalformedID", name, err)
			}
		}
	})
}

// TestCanonicalTime is audit's test for the same three lines, copied with
// them as CONVENTIONS.md requires: truncate rather than round, UTC before
// truncation, and the monotonic reading stripped.
func TestCanonicalTime(t *testing.T) {
	t.Parallel()

	// Truncated, not rounded. 999 nanoseconds must become 0, not 1
	// microsecond: rounding up would move an instant into the future, and a
	// liveness deadline derived from it with it.
	in := time.Date(2026, time.October, 23, 9, 30, 45, 123456999, time.UTC)
	got := CanonicalTime(in)
	if got.Nanosecond() != 123456000 {
		t.Fatalf("CanonicalTime kept %d nanoseconds, want 123456000 (truncated, not rounded)", got.Nanosecond())
	}

	// UTC, whatever zone came in, and the same instant either way.
	zone := time.FixedZone("UTC+7", 7*3600)
	local := in.In(zone)
	if !CanonicalTime(local).Equal(got) {
		t.Fatal("CanonicalTime depends on the zone of its argument")
	}
	if CanonicalTime(local).Location() != time.UTC {
		t.Fatal("CanonicalTime did not convert to UTC")
	}

	// Idempotent, which is what every Validate in this package relies on when
	// it compares a stored instant against CanonicalTime of itself.
	if !CanonicalTime(got).Equal(got) {
		t.Fatal("CanonicalTime is not idempotent")
	}

	// The monotonic reading is stripped, so a time.Now() value and its
	// serialized form compare equal.
	now := CanonicalTime(time.Now())
	if now.Round(0) != now {
		t.Fatal("CanonicalTime left a monotonic reading attached")
	}
}

func TestClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC)
	c := NewFixedClock(start)
	if !c.Now().Equal(start) {
		t.Fatal("a fixed clock does not return its instant")
	}
	c.Advance(90 * time.Minute)
	if !c.Now().Equal(start.Add(90 * time.Minute)) {
		t.Fatal("Advance did not move the clock")
	}
	if (SystemClock{}).Now().IsZero() {
		t.Fatal("the system clock returned the zero time")
	}
}

func TestThresholdValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		th   Threshold
		want error
	}{
		"2 of 2":                     {Threshold{2, 2}, nil},
		"2 of 3":                     {Threshold{2, 3}, nil},
		"3 of 5":                     {Threshold{3, 5}, nil},
		"255 of 255":                 {Threshold{255, 255}, nil},
		"1 of 3 (system could open)": {Threshold{1, 3}, ErrInvalidThreshold},
		"0 of 3":                     {Threshold{0, 3}, ErrInvalidThreshold},
		"negative required":          {Threshold{-1, 3}, ErrInvalidThreshold},
		"4 of 3 (unreachable)":       {Threshold{4, 3}, ErrInvalidThreshold},
		"2 of 256 (beyond GF(256))":  {Threshold{2, 256}, ErrInvalidThreshold},
		"the zero threshold":         {Threshold{}, ErrInvalidThreshold},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := tc.th.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}

	if got := (Threshold{2, 3}).String(); got != "2-of-3" {
		t.Fatalf("String = %q", got)
	}
}

func TestGeneration(t *testing.T) {
	t.Parallel()

	if err := Generation(0).Validate(); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("generation 0 validates: %v", err)
	}
	if err := FirstGeneration.Validate(); err != nil {
		t.Fatalf("the first generation does not validate: %v", err)
	}
	if got := FirstGeneration.Next(); got != 2 {
		t.Fatalf("Next = %d", got)
	}
	if got := Generation(3).String(); got != "g3" {
		t.Fatalf("String = %q", got)
	}
}

func TestSealValidate(t *testing.T) {
	t.Parallel()

	good := testSeal(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("the baseline seal does not validate: %v", err)
	}

	tests := map[string]struct {
		mutate func(s *Seal)
		want   error
	}{
		"no tenant":    {func(s *Seal) { s.Tenant = TenantID{} }, ErrInvalidArgument},
		"no id":        {func(s *Seal) { s.ID = SealID{} }, ErrInvalidArgument},
		"generation 0": {func(s *Seal) { s.Generation = 0 }, ErrInvalidArgument},
		"a 1-of-3 threshold": {func(s *Seal) {
			s.Threshold = Threshold{1, 3}
		}, ErrInvalidThreshold},
		"no commitment": {func(s *Seal) { s.Commitment = KeyCommitment{} }, ErrInvalidArgument},
		"too few custodians": {func(s *Seal) {
			s.Custodians = s.Custodians[:2]
		}, ErrInvalidArgument},
		"a custodian named twice": {func(s *Seal) {
			s.Custodians[1].ID = s.Custodians[0].ID
		}, ErrInvalidArgument},
		"a share index assigned twice": {func(s *Seal) {
			s.Custodians[1].Index = s.Custodians[0].Index
		}, ErrInvalidArgument},
		"a custodian with no id": {func(s *Seal) {
			s.Custodians[0].ID = CustodianID{}
		}, ErrInvalidArgument},
		"a custodian at index 0": {func(s *Seal) {
			s.Custodians[0].Index = 0
		}, ErrInvalidShare},
		"an unknown holder kind": {func(s *Seal) {
			s.Custodians[0].Holder = HolderKind("offsite")
		}, ErrInvalidArgument},
		// CHARTER property 1, from both directions.
		"two shares inside the deployment": {func(s *Seal) {
			s.Custodians[0].Holder = HolderSystem
			s.Custodians[1].Holder = HolderSystem
		}, ErrInvalidArgument},
		"a schedule that could misfire": {func(s *Seal) {
			s.Liveness.Grace = 0
		}, ErrInvalidSchedule},
		"no creation instant": {func(s *Seal) { s.CreatedAt = time.Time{} }, ErrInvalidArgument},
		"no sealing instant":  {func(s *Seal) { s.SealedAt = time.Time{} }, ErrInvalidArgument},
		"a non-canonical instant": {func(s *Seal) {
			s.SealedAt = s.SealedAt.Add(time.Nanosecond)
		}, ErrInvalidArgument},
		"sealed before it was created": {func(s *Seal) {
			s.SealedAt = s.CreatedAt.Add(-time.Hour)
		}, ErrInvalidArgument},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := testSeal(t)
			tc.mutate(&s)
			if err := s.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSealNeverLetsTheDeploymentReachItsOwnThreshold is CHARTER property 1
// stated as the method that reports it, over every threshold the API accepts.
func TestSealNeverLetsTheDeploymentReachItsOwnThreshold(t *testing.T) {
	t.Parallel()

	seal := testSeal(t)
	if seal.SystemHeldShares() != 1 {
		t.Fatalf("the baseline seal puts %d shares inside the deployment, want 1", seal.SystemHeldShares())
	}
	if seal.IsSystemSufficient() {
		t.Fatal("the baseline seal reports the deployment as sufficient")
	}

	// A seal with no system custodian is a stronger arrangement and must be
	// accepted.
	none := testSeal(t)
	none.Custodians[0].Holder = HolderExternal
	if err := none.Validate(); err != nil {
		t.Fatalf("a seal the deployment holds no share of does not validate: %v", err)
	}
	if none.SystemHeldShares() != 0 || none.IsSystemSufficient() {
		t.Fatal("a seal with no system custodian is reported wrongly")
	}
	if _, ok := none.SystemCustodian(); ok {
		t.Fatal("SystemCustodian found one where there is none")
	}
}

func TestSealAcceptsHeldShare(t *testing.T) {
	t.Parallel()

	seal := testSeal(t)
	system, ok := seal.SystemCustodian()
	if !ok {
		t.Fatal("the baseline seal has no system custodian")
	}
	material := bytes.Repeat([]byte{0x33}, KeySize)

	good, err := NewShare(seal.ID, seal.Generation, system.Index, material)
	if err != nil {
		t.Fatalf("NewShare: %v", err)
	}
	if err := seal.AcceptsHeldShare(good); err != nil {
		t.Fatalf("the deployment's own share is refused: %v", err)
	}

	otherSeal, err := ParseSealID("ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("ParseSealID: %v", err)
	}
	// An external custodian's index, which must be refused: a share assigned
	// to a lawyer turning up in the deployment's storage is the distribution
	// of shares silently changing.
	var externalIndex ShareIndex
	for _, c := range seal.Custodians {
		if c.Holder == HolderExternal {
			externalIndex = c.Index
			break
		}
	}

	tests := map[string]struct {
		share func(t *testing.T) Share
		want  error
	}{
		"another seal's share": {
			share: func(t *testing.T) Share { return mustShare(t, otherSeal, seal.Generation, system.Index, material) },
			want:  ErrForeignShare,
		},
		"a superseded generation": {
			share: func(t *testing.T) Share {
				return mustShare(t, seal.ID, seal.Generation.Next(), system.Index, material)
			},
			want: ErrForeignShare,
		},
		"an external custodian's index": {
			share: func(t *testing.T) Share { return mustShare(t, seal.ID, seal.Generation, externalIndex, material) },
			want:  ErrInvalidArgument,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := seal.AcceptsHeldShare(tc.share(t)); !errors.Is(err, tc.want) {
				t.Fatalf("AcceptsHeldShare error = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("a seal with no system custodian holds nothing", func(t *testing.T) {
		t.Parallel()

		none := testSeal(t)
		none.Custodians[0].Holder = HolderExternal
		if err := none.AcceptsHeldShare(good); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("error = %v, want ErrInvalidArgument", err)
		}
	})
}

func TestSealCloneIsDeep(t *testing.T) {
	t.Parallel()

	seal := testSeal(t)
	clone := seal.Clone()
	clone.Custodians[0].ID = mustCustodianID(t, "someone-else")
	clone.Liveness.Escalations[0].Channel = "carrier-pigeon"

	if seal.Custodians[0].ID == clone.Custodians[0].ID {
		t.Fatal("Clone aliased the custodian slice")
	}
	if seal.Liveness.Escalations[0].Channel == clone.Liveness.Escalations[0].Channel {
		t.Fatal("Clone aliased the escalation slice")
	}
}

// TestOnlyTheThresholdCanUnseal is CHARTER property 2 at the release-condition
// level, asserted exhaustively over the closed set: a liveness lapse and a
// human act release a share, and the only condition that unseals is the one
// whose precondition is that the threshold has already been reached.
func TestOnlyTheThresholdCanUnseal(t *testing.T) {
	t.Parallel()

	unsealing := 0
	for _, kind := range ReleaseConditionKinds() {
		if err := kind.Validate(); err != nil {
			t.Fatalf("%s does not validate: %v", kind, err)
		}
		switch effect := kind.Effect(); kind {
		case ReleaseByLivenessLapse:
			if effect != EffectShareRelease {
				t.Fatalf("a liveness lapse has effect %q, want %q: "+
					"a dead-man's switch that unseals is one that eventually misfires", effect, EffectShareRelease)
			}
		case ReleaseByHumanAct:
			if effect != EffectShareRelease {
				t.Fatalf("a human act has effect %q, want %q: a custodian holds a share, and that is all they hold",
					effect, EffectShareRelease)
			}
		case ReleaseByThreshold:
			if effect != EffectUnseal {
				t.Fatalf("the threshold has effect %q, want %q", effect, EffectUnseal)
			}
		}
		if kind.Effect() == EffectUnseal {
			unsealing++
		}
	}
	if unsealing != 1 {
		t.Fatalf("%d of %d release conditions can unseal, want exactly 1", unsealing, len(ReleaseConditionKinds()))
	}

	// An unrecognised kind releases nothing, rather than defaulting to the
	// most permissive answer.
	unknown := ReleaseConditionKind("court_order")
	if got := unknown.Effect(); got != EffectNone {
		t.Fatalf("an unrecognised condition has effect %q, want %q", got, EffectNone)
	}
	if err := unknown.Validate(); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("an unrecognised condition validates: %v", err)
	}
}

func TestCeremonyValidate(t *testing.T) {
	t.Parallel()

	good := testCeremony(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("the baseline ceremony does not validate: %v", err)
	}

	tests := map[string]struct {
		mutate func(c *Ceremony)
		want   error
	}{
		"no tenant":         {func(c *Ceremony) { c.Tenant = TenantID{} }, ErrInvalidArgument},
		"no id":             {func(c *Ceremony) { c.ID = CeremonyID{} }, ErrInvalidArgument},
		"no seal":           {func(c *Ceremony) { c.Seal = SealID{} }, ErrInvalidArgument},
		"generation 0":      {func(c *Ceremony) { c.Generation = 0 }, ErrInvalidArgument},
		"unknown condition": {func(c *Ceremony) { c.Condition = "court_order" }, ErrInvalidArgument},
		// The effect must be the one that condition has: a record claiming a
		// lapse unsealed something is a record that must not be storable.
		"an effect its condition does not have": {func(c *Ceremony) {
			c.Condition, c.Effect = ReleaseByLivenessLapse, EffectUnseal
		}, ErrInvalidArgument},
		"no participants":        {func(c *Ceremony) { c.Participants = nil }, ErrInvalidArgument},
		"an empty participant":   {func(c *Ceremony) { c.Participants[0] = CustodianID{} }, ErrInvalidArgument},
		"a negative share count": {func(c *Ceremony) { c.SharesPresented = -1 }, ErrInvalidArgument},
		"no outcome":             {func(c *Ceremony) { c.Outcome = "" }, ErrInvalidArgument},
		"an unknown outcome":     {func(c *Ceremony) { c.Outcome = "maybe" }, ErrInvalidArgument},
		"an oversized reason": {func(c *Ceremony) {
			c.Reason = strings.Repeat("x", maxReasonLen+1)
		}, ErrInvalidArgument},
		"no instant":              {func(c *Ceremony) { c.At = time.Time{} }, ErrInvalidArgument},
		"a non-canonical instant": {func(c *Ceremony) { c.At = c.At.Add(time.Nanosecond) }, ErrInvalidArgument},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := testCeremony(t)
			tc.mutate(&c)
			if err := c.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}

	// Refusals and failures are storable: CHARTER.md's "including the failed
	// ones, which are the interesting signal".
	for _, outcome := range CeremonyOutcomes() {
		c := testCeremony(t)
		c.Outcome = outcome
		c.Reason = "three shares presented, the set failed its commitment"
		if err := c.Validate(); err != nil {
			t.Fatalf("a %s ceremony does not validate: %v", outcome, err)
		}
	}

	t.Run("Equal distinguishes a retry from a conflict", func(t *testing.T) {
		t.Parallel()

		a, b := testCeremony(t), testCeremony(t)
		if !a.Equal(b) {
			t.Fatal("two identical ceremonies do not compare equal")
		}
		b.Reason = "different"
		if a.Equal(b) {
			t.Fatal("two ceremonies differing in their reason compare equal")
		}
		c := testCeremony(t)
		c.Participants = append(c.Participants, mustCustodianID(t, "extra"))
		if a.Equal(c) {
			t.Fatal("two ceremonies with different participants compare equal")
		}
	})
}

func TestAttemptValidate(t *testing.T) {
	t.Parallel()

	base := testAttempt(t)
	if err := base.Validate(); err != nil {
		t.Fatalf("the baseline attempt does not validate: %v", err)
	}

	// Every kind and every outcome must be recordable, and a channel is
	// required for exactly the two kinds that have one.
	for _, kind := range AttemptKinds() {
		for _, outcome := range AttemptOutcomes() {
			a := testAttempt(t)
			a.Kind, a.Outcome = kind, outcome
			switch kind {
			case AttemptProofOfLife, AttemptNotification:
				a.Channel = "email"
			case AttemptShareRelease, AttemptUnseal:
				a.Channel = ""
			}
			if err := a.Validate(); err != nil {
				t.Fatalf("a %s/%s attempt does not validate: %v", kind, outcome, err)
			}
		}
	}

	tests := map[string]struct {
		mutate func(a *Attempt)
		want   error
	}{
		"no tenant":       {func(a *Attempt) { a.Tenant = TenantID{} }, ErrInvalidArgument},
		"no seal":         {func(a *Attempt) { a.Seal = SealID{} }, ErrInvalidArgument},
		"generation 0":    {func(a *Attempt) { a.Generation = 0 }, ErrInvalidArgument},
		"unknown kind":    {func(a *Attempt) { a.Kind = "pondered" }, ErrInvalidArgument},
		"no outcome":      {func(a *Attempt) { a.Outcome = "" }, ErrInvalidArgument},
		"unknown outcome": {func(a *Attempt) { a.Outcome = "probably" }, ErrInvalidArgument},
		"no actor":        {func(a *Attempt) { a.Actor = CustodianID{} }, ErrInvalidArgument},
		"a notification with no channel": {func(a *Attempt) {
			a.Kind, a.Channel = AttemptNotification, ""
		}, ErrInvalidArgument},
		"an unseal with a channel": {func(a *Attempt) {
			a.Kind, a.Channel = AttemptUnseal, "email"
		}, ErrInvalidArgument},
		"an oversized reason": {func(a *Attempt) {
			a.Reason = strings.Repeat("x", maxReasonLen+1)
		}, ErrInvalidArgument},
		"no instant":              {func(a *Attempt) { a.At = time.Time{} }, ErrInvalidArgument},
		"a non-canonical instant": {func(a *Attempt) { a.At = a.At.Add(time.Nanosecond) }, ErrInvalidArgument},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := testAttempt(t)
			tc.mutate(&a)
			if err := a.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestProofOfLifeValidateAndEqual(t *testing.T) {
	t.Parallel()

	good := testProofOfLife(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("the baseline proof does not validate: %v", err)
	}

	for name, mutate := range map[string]func(p *ProofOfLife){
		"no seal":                 func(p *ProofOfLife) { p.Seal = SealID{} },
		"no id":                   func(p *ProofOfLife) { p.ID = ProofID{} },
		"no channel":              func(p *ProofOfLife) { p.Channel = "" },
		"no instant":              func(p *ProofOfLife) { p.At = time.Time{} },
		"a non-canonical instant": func(p *ProofOfLife) { p.At = p.At.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := testProofOfLife(t)
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("expected a refusal")
			} else if !errors.Is(err, ErrInvalidArgument) && !errors.Is(err, ErrMalformedID) {
				t.Fatalf("error = %v, want ErrInvalidArgument or ErrMalformedID", err)
			}
		})
	}

	other := testProofOfLife(t)
	other.Channel = "sms"
	if !good.Equal(testProofOfLife(t)) {
		t.Fatal("two identical proofs do not compare equal")
	}
	if good.Equal(other) {
		t.Fatal("two proofs on different channels compare equal")
	}
}

// ---- fixtures ----

func fixtureNow() time.Time {
	return CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))
}

func fixtureSchedule() LivenessSchedule {
	return LivenessSchedule{
		Since:   fixtureNow(),
		CheckIn: 30 * 24 * time.Hour,
		Escalations: []Escalation{
			{After: 0, Channel: "email"},
			{After: 7 * 24 * time.Hour, Channel: "sms"},
		},
		Grace: 14 * 24 * time.Hour,
	}
}

func testSeal(t *testing.T) Seal {
	t.Helper()

	return Seal{
		Tenant:     mustTenantID(t, "tenant-1"),
		ID:         mustRenderingSealID(t),
		Generation: FirstGeneration,
		Threshold:  Threshold{Required: 2, Total: 3},
		Commitment: CommitKey(mustRenderingSealID(t), FirstGeneration, mustKey(t, 0x44)),
		Custodians: []Custodian{
			{ID: mustCustodianID(t, "deployment"), Holder: HolderSystem, Index: 17},
			{ID: mustCustodianID(t, "lawyer"), Holder: HolderExternal, Index: 200},
			{ID: mustCustodianID(t, "sibling"), Holder: HolderExternal, Index: 5},
		},
		Liveness:  fixtureSchedule(),
		CreatedAt: fixtureNow(),
		SealedAt:  fixtureNow(),
	}
}

func testCeremony(t *testing.T) Ceremony {
	t.Helper()

	return Ceremony{
		Tenant:          mustTenantID(t, "tenant-1"),
		ID:              mustCeremonyID(t, "0000000000000000000000000000ce01"),
		Seal:            mustRenderingSealID(t),
		Generation:      FirstGeneration,
		Condition:       ReleaseByThreshold,
		Effect:          EffectUnseal,
		Participants:    []CustodianID{mustCustodianID(t, "lawyer"), mustCustodianID(t, "sibling")},
		SharesPresented: 2,
		SharesRequired:  2,
		Outcome:         CeremonyCompleted,
		At:              fixtureNow(),
	}
}

func testAttempt(t *testing.T) Attempt {
	t.Helper()

	return Attempt{
		Tenant:     mustTenantID(t, "tenant-1"),
		Seal:       mustRenderingSealID(t),
		Generation: FirstGeneration,
		Kind:       AttemptNotification,
		Outcome:    AttemptFailed,
		Actor:      mustCustodianID(t, "deployment"),
		Channel:    "sms",
		Reason:     "the gateway refused the message",
		At:         fixtureNow(),
	}
}

func testProofOfLife(t *testing.T) ProofOfLife {
	t.Helper()

	return ProofOfLife{
		Seal:    mustRenderingSealID(t),
		ID:      mustProofID(t, "00000000000000000000000000000f01"),
		At:      fixtureNow(),
		Channel: "email",
	}
}

func mustTenantID(t *testing.T, s string) TenantID {
	t.Helper()

	id, err := ParseTenantID(s)
	if err != nil {
		t.Fatalf("ParseTenantID(%q): %v", s, err)
	}
	return id
}

func mustCustodianID(t *testing.T, s string) CustodianID {
	t.Helper()

	id, err := ParseCustodianID(s)
	if err != nil {
		t.Fatalf("ParseCustodianID(%q): %v", s, err)
	}
	return id
}

func mustCeremonyID(t *testing.T, s string) CeremonyID {
	t.Helper()

	id, err := ParseCeremonyID(s)
	if err != nil {
		t.Fatalf("ParseCeremonyID(%q): %v", s, err)
	}
	return id
}

func mustProofID(t *testing.T, s string) ProofID {
	t.Helper()

	id, err := ParseProofID(s)
	if err != nil {
		t.Fatalf("ParseProofID(%q): %v", s, err)
	}
	return id
}

func mustShare(t *testing.T, seal SealID, generation Generation, index ShareIndex, material []byte) Share {
	t.Helper()

	s, err := NewShare(seal, generation, index, material)
	if err != nil {
		t.Fatalf("NewShare: %v", err)
	}
	return s
}

func mustKey(t *testing.T, fill byte) SealedKey {
	t.Helper()

	key, err := SealedKeyFrom(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatalf("SealedKeyFrom: %v", err)
	}
	return key
}
