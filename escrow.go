// Package escrow seals a key under M-of-N shares held by named custodians,
// and releases it only under a recorded ceremony.
//
// It exists because access control is enforced by whoever administers access
// control. No policy engine can promise that no future rule will grant
// access, because rules are mutable and administrators exist. For the cases
// where "private under all circumstances" has to survive the administrator,
// the operator, a subpoena and every future policy change, the only
// mechanism left is one where the system **cannot** decrypt — and this module
// is that tier's custody mechanism. The cost is total and must be stated to
// users rather than discovered by them: a crypto-sealed document cannot be
// indexed, extracted, summarised or searched.
//
// What it does not do, per CHARTER.md: envelope encryption itself (that is
// keyring — this module seals keyring's key-encryption keys, it does not
// implement wrapping), authorization rules (that is iam), or any knowledge of
// what the sealed thing is.
//
// # Five safety properties, and where each one lives
//
// The design is driven by the failure rather than the feature, because
// releasing a sealed thing early cannot be undone. Each property is enforced
// by a type or a method rather than by a code path that has to remember it:
//
//  1. **The system holds at most one share and is never sufficient.**
//     Threshold.Validate refuses a required count below MinThreshold;
//     Seal.Validate refuses more than MaxSystemHeldShares shares inside the
//     deployment and refuses any seal the deployment could open alone; the
//     SealStore port has no plural for the share it holds, and both stores
//     refuse a second with ErrShareAlreadyHeld.
//  2. **A liveness lapse releases a share, not the content.** The effect of a
//     release condition is a function of its kind, and only
//     ReleaseByThreshold — whose precondition *is* the threshold — has
//     EffectUnseal. EvaluateLiveness cannot return a key.
//  3. **Escalating notification, then a grace period any single proof of life
//     cancels.** LivenessSchedule.Validate refuses a schedule with fewer than
//     MinEscalationChannels independent channels or a non-positive grace
//     period, and the whole timeline is derived from the most recent proof, so
//     one proof moves every subsequent instant.
//  4. **Re-seal rotates the key.** Rotate mints a new key, so previously
//     distributed shares become useless rather than superseded: they fail by
//     their binding (ErrForeignShare) and, if that binding is rewritten, by
//     the commitment (ErrReconstructionUnverified).
//  5. **The ceremony must be executable by someone who cannot ask the
//     author.** Not yet delivered: the procedure documentation is the next
//     increment. See README.md's status section.
//
// # Reconstruction is verified, which is the module's central claim
//
// Shamir's scheme is not authenticated. A custodian who supplies a corrupted
// or fabricated share causes a *wrong key* to be interpolated, silently, with
// no error — measured, not assumed. So every Seal records a KeyCommitment
// over the key its generation sealed, and Reconstruct returns
// ErrReconstructionUnverified and **no key** rather than something key-shaped
// that is not the key.
//
// # Wiring it
//
//	plan := escrow.Plan{
//		Threshold: escrow.Threshold{Required: 3, Total: 5},
//		Holders:   []escrow.CustodianID{deployment, lawyer, sibling, notary, friend},
//		System:    deployment, // the one share this deployment holds
//		Liveness:  schedule,
//	}
//	seal, key, shares, err := escrow.Create(tenant, plan, escrow.SystemClock{})
//	if err != nil {
//		return err
//	}
//	defer key.Destroy() // use it, then destroy it: after this it exists only as shares
//
//	if err := store.CreateSeal(ctx, seal); err != nil {
//		return err
//	}
//	for _, share := range shares {
//		// Each custodian's share leaves the deployment; the system's one stays.
//		...
//	}
//
// # This file
//
// Every value object lives in internal/domain and nowhere else; the ports and
// the in-memory store in internal/sealstore, the threshold arithmetic in
// internal/threshold, the Postgres adapter in internal/pgstore, the schema in
// internal/migrate, the audit mapping in internal/trail. This file
// re-exports what a consumer must name as type aliases, so a Share this
// module produces and an escrow.Share a consumer holds are the identical
// type, not a copy that needs converting at the boundary.
//
// It carries the aliases, the sentinels, the exported constants **and the
// module's entry points** — every function here is a one-line forward to an
// internal package. It holds no logic: a facade that hides what the module is
// for is not a facade, and Go's internal rule makes anything not re-exported
// here unreachable from outside the module.
package escrow

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/laenenai/audit"

	"github.com/laenenai/escrow/internal/domain"
	"github.com/laenenai/escrow/internal/migrate"
	"github.com/laenenai/escrow/internal/notify"
	"github.com/laenenai/escrow/internal/pgstore"
	"github.com/laenenai/escrow/internal/sealstore"
	"github.com/laenenai/escrow/internal/threshold"
	"github.com/laenenai/escrow/internal/trail"
)

type (
	// SealStore is the port every storage adapter implements, and the one
	// place this module persists anything. See sealstore.SealStore, and
	// escrowtest.RunSealStoreSuite for the authoritative contract — in
	// particular for the four refusals that are safety properties rather than
	// conveniences.
	SealStore = sealstore.SealStore
	// MemoryConfig configures NewMemory. See sealstore.MemoryConfig.
	MemoryConfig = sealstore.MemoryConfig
	// Config configures Open: the Postgres handle and the tenant the store is
	// scoped to. See pgstore.Config.
	Config = pgstore.Config
	// DB is the narrow Postgres handle Open reads and writes through, which a
	// tenancy data-plane handle satisfies without this module depending on
	// tenancy at the port. See pgstore.DB.
	DB = pgstore.DB
	// MigrateConfig configures Migrate. See migrate.Config.
	MigrateConfig = migrate.Config
	// Applied describes one migration's state. See migrate.Applied.
	Applied = migrate.Applied

	// Notifier is the port one notification channel implements. **Port only
	// in this increment** — there are no channel adapters. See notify.Notifier
	// for the two properties a channel must have and why there is not yet a
	// conformance suite.
	Notifier = notify.Notifier

	// Trail records attempts into an audit log: every proof of life,
	// notification, share release and unseal attempt, including the failed
	// ones. See trail.Trail.
	Trail = trail.Trail
	// Log is the audit port a Trail records through, re-exported so a consumer
	// can name it without importing audit at the call site. It is
	// github.com/laenenai/audit's Log.
	Log = audit.Log

	// Plan is the custody arrangement for one generation of a seal: the
	// threshold, who holds the shares, and which one is the deployment. See
	// threshold.Plan.
	Plan = threshold.Plan

	// Seal is one sealed key's record: the custody arrangement, without the
	// key or the shares. See domain.Seal.
	Seal = domain.Seal
	// SealedKey is the key a seal protects, zeroizable and non-rendering. See
	// domain.SealedKey.
	SealedKey = domain.SealedKey
	// Share is one share of a split key, bound to the seal and generation it
	// was cut under, zeroizable and non-rendering. See domain.Share.
	Share = domain.Share
	// ShareIndex is a share's x-coordinate — not an ordinal. See
	// domain.ShareIndex.
	ShareIndex = domain.ShareIndex
	// KeyCommitment binds a seal and generation to the exact key that
	// generation sealed, and is what makes reconstruction verified rather than
	// hopeful. See domain.KeyCommitment.
	KeyCommitment = domain.KeyCommitment
	// Threshold is a seal's M-of-N. See domain.Threshold.
	Threshold = domain.Threshold
	// Generation is which sealing a key, a commitment and a share belong to.
	// See domain.Generation.
	Generation = domain.Generation
	// Custodian is one named holder of one share. See domain.Custodian.
	Custodian = domain.Custodian
	// HolderKind says whether a share is inside the deployment or outside it.
	// See domain.HolderKind.
	HolderKind = domain.HolderKind

	// LivenessSchedule is a seal's dead-man's-switch configuration. See
	// domain.LivenessSchedule.
	LivenessSchedule = domain.LivenessSchedule
	// Escalation is one step of the notification ladder. See
	// domain.Escalation.
	Escalation = domain.Escalation
	// ProofOfLife is one recorded demonstration that the principal is alive.
	// See domain.ProofOfLife.
	ProofOfLife = domain.ProofOfLife
	// Liveness is EvaluateLiveness's answer. See domain.Liveness.
	Liveness = domain.Liveness
	// LivenessState is where a seal's dead-man's switch has got to. See
	// domain.LivenessState.
	LivenessState = domain.LivenessState
	// Notification is one escalation that has become due. See
	// domain.Notification.
	Notification = domain.Notification

	// ReleaseConditionKind names a circumstance under which something is
	// released. See domain.ReleaseConditionKind.
	ReleaseConditionKind = domain.ReleaseConditionKind
	// ReleaseEffect is what a satisfied condition hands over — a share, or
	// the content. See domain.ReleaseEffect.
	ReleaseEffect = domain.ReleaseEffect
	// Ceremony is the record of one occasion on which a release condition was
	// evaluated and acted on. See domain.Ceremony.
	Ceremony = domain.Ceremony
	// CeremonyOutcome is how a recorded ceremony ended. See
	// domain.CeremonyOutcome.
	CeremonyOutcome = domain.CeremonyOutcome

	// Attempt is one event in the trail. See domain.Attempt.
	Attempt = domain.Attempt
	// AttemptKind names what was attempted. See domain.AttemptKind.
	AttemptKind = domain.AttemptKind
	// AttemptOutcome is how an attempt ended. See domain.AttemptOutcome.
	AttemptOutcome = domain.AttemptOutcome

	// TenantID references the tenant a seal belongs to, opaquely. See
	// domain.TenantID.
	TenantID = domain.TenantID
	// SealID identifies one seal globally and permanently. See domain.SealID.
	SealID = domain.SealID
	// CustodianID references one named custodian, opaquely. See
	// domain.CustodianID.
	CustodianID = domain.CustodianID
	// CeremonyID identifies one recorded ceremony. See domain.CeremonyID.
	CeremonyID = domain.CeremonyID
	// ProofID identifies one recorded proof of life. See domain.ProofID.
	ProofID = domain.ProofID
	// ChannelID names one notification channel in the caller's vocabulary.
	// See domain.ChannelID.
	ChannelID = domain.ChannelID

	// Clock abstracts the current time. See domain.Clock.
	Clock = domain.Clock
	// SystemClock is the production Clock. See domain.SystemClock.
	SystemClock = domain.SystemClock
	// FixedClock is a test Clock. See domain.FixedClock.
	FixedClock = domain.FixedClock
)

// Sentinel errors returned across every package boundary in this module. See
// internal/domain/errors.go for their full documentation, in particular why
// ErrReconstructionUnverified exists at all and why it names nothing.
var (
	// ErrInvalidConfig is domain.ErrInvalidConfig: the module was wired up
	// wrongly and no retry will help.
	ErrInvalidConfig = domain.ErrInvalidConfig
	// ErrInvalidArgument is domain.ErrInvalidArgument: a bug at the call
	// site.
	ErrInvalidArgument = domain.ErrInvalidArgument
	// ErrMalformedID is domain.ErrMalformedID: a string is not a canonical
	// identifier.
	ErrMalformedID = domain.ErrMalformedID
	// ErrInvalidThreshold is domain.ErrInvalidThreshold: the M-of-N was
	// refused. Its lower bound on M is CHARTER.md's first safety property, so
	// catching this is catching an attempt to create a seal the deployment
	// could open alone.
	ErrInvalidThreshold = domain.ErrInvalidThreshold
	// ErrInvalidSchedule is domain.ErrInvalidSchedule: a liveness schedule
	// that could misfire — too few independent channels, no grace period, a
	// ladder that does not advance.
	ErrInvalidSchedule = domain.ErrInvalidSchedule
	// ErrInvalidKeyMaterial is domain.ErrInvalidKeyMaterial.
	ErrInvalidKeyMaterial = domain.ErrInvalidKeyMaterial
	// ErrInvalidShare is domain.ErrInvalidShare: a share is not structurally
	// usable, or an exported envelope was damaged.
	ErrInvalidShare = domain.ErrInvalidShare

	// ErrSealExists is domain.ErrSealExists.
	ErrSealExists = domain.ErrSealExists
	// ErrSealNotFound is domain.ErrSealNotFound. It deliberately does not
	// distinguish "no such seal" from "not yours".
	ErrSealNotFound = domain.ErrSealNotFound
	// ErrShareAlreadyHeld is domain.ErrShareAlreadyHeld: CHARTER.md's first
	// safety property as a sentinel.
	ErrShareAlreadyHeld = domain.ErrShareAlreadyHeld
	// ErrNoHeldShare is domain.ErrNoHeldShare, which is an ordinary state
	// rather than a malfunction.
	ErrNoHeldShare = domain.ErrNoHeldShare

	// ErrForeignShare is domain.ErrForeignShare: a share does not belong to
	// the seal and generation being reconstructed.
	ErrForeignShare = domain.ErrForeignShare
	// ErrDuplicateShare is domain.ErrDuplicateShare: one custodian cannot
	// satisfy a threshold by presenting one share M times.
	ErrDuplicateShare = domain.ErrDuplicateShare
	// ErrInsufficientShares is domain.ErrInsufficientShares.
	ErrInsufficientShares = domain.ErrInsufficientShares
	// ErrReconstructionUnverified is domain.ErrReconstructionUnverified: the
	// sentinel this module exists to be able to return, rather than a wrong
	// key with no error.
	ErrReconstructionUnverified = domain.ErrReconstructionUnverified

	// ErrUnavailable is domain.ErrUnavailable: the one sentinel here that
	// invites a retry.
	ErrUnavailable = domain.ErrUnavailable
	// ErrStorage is domain.ErrStorage.
	ErrStorage = domain.ErrStorage
)

const (
	// KeySize is the length in bytes of every key this module seals: 32. See
	// domain.KeySize.
	KeySize = domain.KeySize
	// Redacted is the placeholder every rendering of secret material yields.
	// See domain.Redacted.
	Redacted = domain.Redacted

	// MinThreshold is the smallest required share count this module accepts:
	// 2, because the deployment may hold one share. See domain.MinThreshold.
	MinThreshold = domain.MinThreshold
	// MaxShares is the largest total share count: 255, the field's limit. See
	// domain.MaxShares.
	MaxShares = domain.MaxShares
	// MaxSystemHeldShares is how many shares the deployment may hold for one
	// seal: 1. See domain.MaxSystemHeldShares.
	MaxSystemHeldShares = domain.MaxSystemHeldShares
	// FirstGeneration is the generation a seal has when it is created. See
	// domain.FirstGeneration.
	FirstGeneration = domain.FirstGeneration
	// MinEscalationChannels is how many independent channels a schedule must
	// escalate over before a lapse is reachable: 2. See
	// domain.MinEscalationChannels.
	MinEscalationChannels = domain.MinEscalationChannels

	// Schema is the Postgres schema this module owns. See migrate.Schema.
	Schema = migrate.Schema
)

// HolderKind values: whether a share is inside the deployment or outside it.
const (
	// HolderExternal is a custodian whose share lives outside the deployment.
	HolderExternal = domain.HolderExternal
	// HolderSystem is the deployment itself, holding its single share.
	HolderSystem = domain.HolderSystem
)

// LivenessState values, in timeline order. See domain's documentation for
// what each one means and what it does and does not release.
const (
	StateAlive   = domain.StateAlive
	StateOverdue = domain.StateOverdue
	StateGrace   = domain.StateGrace
	StateLapsed  = domain.StateLapsed
)

// ReleaseEffect values: what a satisfied condition hands over.
const (
	EffectNone         = domain.EffectNone
	EffectShareRelease = domain.EffectShareRelease
	EffectUnseal       = domain.EffectUnseal
)

// ReleaseConditionKind values. Exactly one of them has EffectUnseal, and it
// is the one whose precondition is that the threshold has been reached.
const (
	ReleaseByHumanAct      = domain.ReleaseByHumanAct
	ReleaseByThreshold     = domain.ReleaseByThreshold
	ReleaseByLivenessLapse = domain.ReleaseByLivenessLapse
)

// CeremonyOutcome values. The refusals and the failures are recorded
// alongside the completions, because the failed ones are the interesting
// signal.
const (
	CeremonyCompleted = domain.CeremonyCompleted
	CeremonyRefused   = domain.CeremonyRefused
	CeremonyFailed    = domain.CeremonyFailed
)

// AttemptKind values: the four things CHARTER.md requires the trail to
// record.
const (
	AttemptProofOfLife  = domain.AttemptProofOfLife
	AttemptNotification = domain.AttemptNotification
	AttemptShareRelease = domain.AttemptShareRelease
	AttemptUnseal       = domain.AttemptUnseal
)

// AttemptOutcome values.
const (
	AttemptSucceeded = domain.AttemptSucceeded
	AttemptRefused   = domain.AttemptRefused
	AttemptFailed    = domain.AttemptFailed
)

// Create mints a fresh key, cuts it into shares under plan, and returns the
// seal record, the key and the shares. See threshold.Create for what the
// caller owns and must destroy — in particular that this is the only moment
// in the key's life when it exists as a single value.
func Create(tenant TenantID, plan Plan, clock Clock) (Seal, SealedKey, []Share, error) {
	return threshold.Create(tenant, plan, clock)
}

// Rotate mints a *new* key for an existing seal and cuts a new generation of
// shares: CHARTER.md's fourth safety property, which is a new key rather than
// reissued shares precisely so that previously distributed shares become
// useless rather than merely superseded. See threshold.Rotate.
func Rotate(seal Seal, plan Plan, clock Clock) (Seal, SealedKey, []Share, error) {
	return threshold.Rotate(seal, plan, clock)
}

// PlanFrom returns the plan that reproduces a seal's current arrangement, for
// a caller rotating the key without changing custodians. See
// threshold.PlanFrom for what a round trip through it does and does not
// preserve.
func PlanFrom(seal Seal) Plan { return threshold.PlanFrom(seal) }

// Reconstruct interpolates the key of a seal's current generation from shares
// and returns it **only if** it matches the seal's commitment — otherwise
// ErrReconstructionUnverified and no key. See threshold.Reconstruct, whose
// doc comment is the contract: the order of its checks, why every presented
// share is used and no subset is searched, and why the error names nothing.
func Reconstruct(seal Seal, shares []Share) (SealedKey, error) {
	return threshold.Reconstruct(seal, shares)
}

// EvaluateLiveness derives a seal's dead-man's-switch state from its proofs
// of life, as of now. It is a pure function — no clock is read, no timer
// exists, nothing is mutated — which is what makes the module's most
// dangerous logic testable. See domain.Evaluate for the timeline, and for why
// a future-dated proof is clamped rather than ignored.
//
// Its result has no path to a key: the strongest thing it can report is that
// one share is due for release.
func EvaluateLiveness(schedule LivenessSchedule, proofs []ProofOfLife, now time.Time) (Liveness, error) {
	return domain.Evaluate(schedule, proofs, now)
}

// NewSealedKey returns a fresh key read from crypto/rand. Create calls it;
// this is here for a caller that mints the key itself. See
// domain.NewSealedKey.
func NewSealedKey() (SealedKey, error) { return domain.NewSealedKey() }

// SealedKeyFrom returns a SealedKey holding a copy of b, for a caller sealing
// a key it already holds — a keyring KEK, which is the case CHARTER.md names.
// See domain.SealedKeyFrom.
func SealedKeyFrom(b []byte) (SealedKey, error) { return domain.SealedKeyFrom(b) }

// ImportShare parses a share exported by Share.Export: the form a custodian
// holds. See domain.ImportShare, and domain.Share.Export for why the method
// is not called MarshalBinary.
func ImportShare(b []byte) (Share, error) { return domain.ImportShare(b) }

// NewMemory returns an in-memory SealStore scoped to a tenant: the adapter a
// consumer runs its own unit tests against, and the one
// escrowtest.RunSealStoreSuite is demonstrated on. It is not a production
// store — nothing in it survives the process, and a seal whose only record
// was in a process that exited is a seal nobody can run a ceremony against.
// See sealstore.NewMemory.
func NewMemory(cfg MemoryConfig) (SealStore, error) { return sealstore.NewMemory(cfg) }

// Open returns a Postgres-backed SealStore scoped to one tenant: the durable
// store this module exists to provide.
//
// It does not migrate anything — Migrate does, as a different identity with
// privileges this one is deliberately not meant to have. See pgstore.Open.
func Open(ctx context.Context, cfg Config) (SealStore, error) { return pgstore.Open(ctx, cfg) }

// Migrate applies this module's schema to pool: its own schema "escrow", with
// its own goose version table inside it, so a consumer's migrations and this
// module's cannot collide on one version table. It also enables row-level
// security through tenancy.EnableRLS. See migrate.Up.
//
// Calling it again is safe and expected.
func Migrate(ctx context.Context, pool *pgxpool.Pool, cfg MigrateConfig) error {
	return migrate.Up(ctx, pool, cfg)
}

// MigrationStatus reports the state of every embedded migration. See
// migrate.Status.
func MigrationStatus(ctx context.Context, pool *pgxpool.Pool) ([]Applied, error) {
	return migrate.Status(ctx, pool)
}

// NewTrail returns a Trail that records this module's attempts into log,
// which must be an audit.Log already scoped to the tenant whose seals it
// concerns. See trail.New, and trail's package doc for why this module
// depends on audit rather than reimplementing a hash chain.
func NewTrail(log Log) (*Trail, error) { return trail.New(log) }

// CanonicalTime normalizes an instant to UTC at microsecond precision: the
// precision every instant in this module is stored and compared at, and the
// precision Postgres timestamptz holds. Every instant a caller puts into a
// Seal, a ProofOfLife, a Ceremony or an Attempt must come through here. See
// domain.CanonicalTime.
func CanonicalTime(t time.Time) time.Time { return domain.CanonicalTime(t) }

// NewFixedClock returns a test Clock starting at t. See domain.FixedClock.
func NewFixedClock(t time.Time) *FixedClock { return domain.NewFixedClock(t) }

// Identifier constructors and parsers. The identifier types are opaque
// structs with no exported field, so these are the only ways to obtain one —
// see internal/domain/ids.go for why that is load-bearing here rather than
// merely tidy.
var (
	// NewSealID mints a fresh seal id. See domain.NewSealID.
	NewSealID = domain.NewSealID
	// NewCeremonyID mints a fresh ceremony id. See domain.NewCeremonyID.
	NewCeremonyID = domain.NewCeremonyID
	// NewProofID mints a fresh proof-of-life id. See domain.NewProofID.
	NewProofID = domain.NewProofID

	// ParseSealID parses a canonical seal id. See domain.ParseSealID.
	ParseSealID = domain.ParseSealID
	// ParseTenantID parses a tenant id, validating its shape. See
	// domain.ParseTenantID.
	ParseTenantID = domain.ParseTenantID
	// ParseCustodianID parses a custodian id, validating its shape. See
	// domain.ParseCustodianID.
	ParseCustodianID = domain.ParseCustodianID
	// ParseCeremonyID parses a canonical ceremony id. See
	// domain.ParseCeremonyID.
	ParseCeremonyID = domain.ParseCeremonyID
	// ParseProofID parses a canonical proof-of-life id. See
	// domain.ParseProofID.
	ParseProofID = domain.ParseProofID
	// ParseKeyCommitment parses a commitment's 64-character hex form. See
	// domain.ParseKeyCommitment.
	ParseKeyCommitment = domain.ParseKeyCommitment
)

// Closed sets, exposed as functions so that a consumer rendering a UI, and
// the exhaustiveness tests, iterate the set rather than a list maintained
// beside it.
var (
	// LivenessStates returns the closed set of liveness states, in timeline
	// order. See domain.LivenessStates.
	LivenessStates = domain.LivenessStates
	// ReleaseConditionKinds returns the closed set of release conditions. See
	// domain.ReleaseConditionKinds.
	ReleaseConditionKinds = domain.ReleaseConditionKinds
	// CeremonyOutcomes returns the closed set of ceremony outcomes. See
	// domain.CeremonyOutcomes.
	CeremonyOutcomes = domain.CeremonyOutcomes
	// AttemptKinds returns the closed set of attempt kinds. See
	// domain.AttemptKinds.
	AttemptKinds = domain.AttemptKinds
	// AttemptOutcomes returns the closed set of attempt outcomes. See
	// domain.AttemptOutcomes.
	AttemptOutcomes = domain.AttemptOutcomes
)
