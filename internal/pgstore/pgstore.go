// Package pgstore is the Postgres adapter for the SealStore port: the durable
// store this module exists to provide. It passes
// escrowtest.RunSealStoreSuite unchanged, which is the test of whether the
// port's shape survived contact with a real database, and it adds the
// guarantees a generic suite cannot express.
//
// # What Postgres enforces that Go cannot
//
// CHARTER.md's first safety property — the system holds at most one share and
// is never sufficient — is expressed in the Go API by a port with no plural
// for the held share. That is necessary and not sufficient: a second
// goroutine, a second process, or a hand-written INSERT has nothing to say to
// a Go interface. So the schema carries it:
//
//   - escrow.held_share's primary key is (tenant_id, seal_id), so a second
//     share for one seal is **not a representable state**. A second insert
//     raises a unique violation, which this adapter maps onto
//     domain.ErrShareAlreadyHeld, and it does so under concurrency where a
//     read-then-insert in Go would not.
//   - escrow.custodian carries a partial unique index on
//     (tenant_id, seal_id) WHERE holder = 'system', so a seal with two shares
//     inside the deployment cannot be written either.
//   - escrow.seal's CHECK requires threshold_required >= 2, which is the same
//     property stated as a number: the deployment may hold one share.
//
// Tenant isolation is likewise the database's, through
// tenancy.EnableRLS — see internal/migrate's enforce.go for the
// permissive-policy disclosure that determined its shape.
//
// # This store is the tenant authority for the transactions it opens
//
// A store is opened scoped to one tenant, and **every operation runs inside a
// transaction this adapter opens**, which begins by narrowing into
// Config.AppRole with SET LOCAL ROLE and establishing that tenant's
// row-level-security context with set_config. Two consequences a deployment
// must know:
//
//   - It is correct on a plain *pgxpool.Pool. A deployment does not have to
//     route through a tenancy data-plane handle to get isolation, and one
//     that does gets the same context set again with the same value, which
//     is harmless.
//   - It must **not** be given a handle already narrowed to a *different*
//     tenant. SET LOCAL and set_config(..., true) are transaction-scoped, so
//     this adapter's context wins inside its own transactions; a caller that
//     wired tenant A's handle into tenant B's store would get tenant B's
//     rows. The store's Tenant is the authority, by design — but it is a
//     precondition rather than something the adapter can check, so it is
//     stated here and in Config.DB.
//
// Every operation being transactional is deliberate even for the reads. A
// read outside a transaction cannot hold SET LOCAL ROLE, so it would run as
// whatever role the pool connects as — and against a superuser pool, which is
// what a container gives you, row security is bypassed unconditionally and
// every isolation assertion would pass while proving nothing.
//
// # Where the SQL is
//
// Every statement that reads or writes this module's tables is in
// db/queries/*.sql and reaches Go through internal/pgstore/gen, which sqlc
// generates against db/migrations. The reasoning that belongs to a statement
// lives beside it there, as SQL, checked against the schema at generation
// time; this package holds the transaction shape and the conversions into
// domain types, and nothing else.
//
// Two statements are hand-written, and each is a case CONVENTIONS.md's sqlc
// rule names rather than a departure from it: SET LOCAL ROLE, which takes no
// bound parameter so the role name has to reach Postgres as SQL text (it is
// validated as a plain identifier at Open and quoted with
// pgx.Identifier.Sanitize at every use); and the set_config call, which is a
// session function rather than a relation and so is not something sqlc
// models.
//
// # No share material in any error
//
// escrow.held_share.material is the only share material in the schema, and
// Postgres echoes offending values into some of its messages. So this adapter
// maps a SQLSTATE onto a sentinel and **drops everything the database said**
// on every row path. The errors name the seal, the generation and the share
// index, which the caller already holds. See classify, and escrowtest's
// NoShareMaterialLeaksInErrors.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/escrow/internal/domain"
	"github.com/laenenai/escrow/internal/pgstore/gen"
	"github.com/laenenai/escrow/internal/sealstore"
)

// tenantGUC is the session setting every row-level-security policy in this
// system is keyed on. It is the same string tenancy's TenantPredicate uses,
// duplicated here rather than imported because this package must not depend
// on tenancy's pool and registry machinery to set one session variable —
// internal/migrate is the package that imports tenancy, and only for
// EnableRLS.
//
// The duplication is checked rather than hoped for:
// TestTenantGUCMatchesTenancy asserts the two agree.
const tenantGUC = "app.tenant_id"

// DB is the narrow database handle this adapter needs: enough to open a
// transaction, and nothing more.
//
// It is an interface rather than a *pgxpool.Pool so that the data-plane handle
// a tenancy module hands out satisfies it without this module depending on
// that module. *pgxpool.Pool satisfies it, and so does pgx.Tx — where Begin
// opens a savepoint, which is what lets the same code path run nested inside
// a caller's transaction.
//
// It must not be a handle already narrowed to a different tenant than the
// store's: see this package's doc comment.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Config configures Open.
type Config struct {
	// DB is the handle the adapter reads and writes through. Required.
	DB DB

	// Tenant is the tenant this store is scoped to, and the value it
	// establishes as the row-level-security context in every transaction it
	// opens. Required.
	Tenant domain.TenantID

	// AppRole, when set, is a Postgres role the adapter switches into with
	// SET LOCAL ROLE for the duration of every transaction it opens.
	//
	// It is how the single-connection-string deployment model keeps privilege
	// separation: the process connects as the owner, which is the identity
	// that migrated the schema, and narrows itself to the application role
	// for run-time work. SET LOCAL is scoped to one transaction, so it cannot
	// leak across a reused pooled connection.
	//
	// Empty means "whatever role the handle already connects as", which is a
	// valid configuration for a deployment that separates the two identities
	// with two connection strings instead. It is **not** a valid
	// configuration against a superuser handle: a superuser bypasses row
	// security unconditionally, so a store opened that way has tenant
	// isolation in the catalog and none in effect. Nothing in SQL can prevent
	// that, which is why it is said here.
	AppRole string
}

// store is the Postgres SealStore.
type store struct {
	db      DB
	tenant  domain.TenantID
	appRole string
	q       *gen.Queries
}

var _ sealstore.SealStore = (*store)(nil)

// Open returns a Postgres-backed SealStore scoped to cfg.Tenant.
//
// It does not migrate anything — migrate.Up does, as a different identity
// with privileges this one is deliberately not meant to have. It also does
// not probe the catalog to check that row-level security is in effect: that
// probe belongs to tenancy, whose AssertRLSCoverage a deployment's own health
// check calls, and duplicating it here would be this module asserting
// something about a mechanism another module owns.
func Open(_ context.Context, cfg Config) (sealstore.SealStore, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("%w: pgstore: DB is required", domain.ErrInvalidConfig)
	}
	if cfg.Tenant.IsZero() {
		return nil, fmt.Errorf("%w: pgstore: Tenant is required: a store with no tenant could neither scope its rows nor establish a row-level-security context",
			domain.ErrInvalidConfig)
	}
	if cfg.AppRole != "" && !isPlainIdentifier(cfg.AppRole) {
		return nil, fmt.Errorf("%w: pgstore: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit",
			domain.ErrInvalidConfig, cfg.AppRole)
	}
	return &store{db: cfg.DB, tenant: cfg.Tenant, appRole: cfg.AppRole, q: gen.New(nil)}, nil
}

// CreateSeal implements sealstore.SealStore.
func (s *store) CreateSeal(ctx context.Context, seal domain.Seal) error {
	if err := seal.Validate(); err != nil {
		return fmt.Errorf("escrow: create seal: %w", err)
	}
	if seal.Tenant != s.tenant {
		return fmt.Errorf("escrow: create seal: %w: seal belongs to another tenant", domain.ErrInvalidArgument)
	}
	if seal.Generation != domain.FirstGeneration {
		return fmt.Errorf("escrow: create seal: %w: a seal is created at %s and rotated thereafter, not created at %s",
			domain.ErrInvalidArgument, domain.FirstGeneration, seal.Generation)
	}

	return s.inTx(ctx, "create seal", func(q *gen.Queries) error {
		if err := q.InsertSeal(ctx, gen.InsertSealParams{
			TenantID:          s.tenant.String(),
			SealID:            seal.ID.String(),
			Generation:        int64(seal.Generation),
			ThresholdRequired: int32(seal.Threshold.Required), //nolint:gosec // bounded by Threshold.Validate at 255
			ThresholdTotal:    int32(seal.Threshold.Total),    //nolint:gosec // bounded by Threshold.Validate at 255
			Commitment:        seal.Commitment[:],
			CheckInNs:         int64(seal.Liveness.CheckIn),
			GraceNs:           int64(seal.Liveness.Grace),
			LivenessSince:     seal.Liveness.Since,
			CreatedAt:         seal.CreatedAt,
			SealedAt:          seal.SealedAt,
		}); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("escrow: create seal %s: %w", seal.ID, domain.ErrSealExists)
			}
			return fmt.Errorf("escrow: create seal %s: %w", seal.ID, classify(err))
		}
		return s.writeArrangement(ctx, q, seal)
	})
}

// Seal implements sealstore.SealStore.
func (s *store) Seal(ctx context.Context, id domain.SealID) (domain.Seal, error) {
	var out domain.Seal
	err := s.inTx(ctx, "read seal", func(q *gen.Queries) error {
		seal, err := s.readSeal(ctx, q, id)
		if err != nil {
			return err
		}
		out = seal
		return nil
	})
	return out, err
}

// ReplaceSeal implements sealstore.SealStore.
//
// The generation advance, the custodian and escalation replacement and the
// discard of the held share are all in one transaction, which is the whole
// reason this is one method rather than three: a caller that rotated the seal
// and then failed before discarding would leave the deployment holding a
// superseded share, which is both useless and indistinguishable from a
// current one at a glance.
func (s *store) ReplaceSeal(ctx context.Context, seal domain.Seal) error {
	if err := seal.Validate(); err != nil {
		return fmt.Errorf("escrow: replace seal: %w", err)
	}
	if seal.Tenant != s.tenant {
		return fmt.Errorf("escrow: replace seal: %w: seal belongs to another tenant", domain.ErrInvalidArgument)
	}

	return s.inTx(ctx, "replace seal", func(q *gen.Queries) error {
		current, err := s.readSeal(ctx, q, seal.ID)
		if err != nil {
			return err
		}
		if want := current.Generation.Next(); seal.Generation != want {
			return fmt.Errorf("escrow: replace seal %s: %w: generation %s does not follow the stored %s",
				seal.ID, domain.ErrInvalidArgument, seal.Generation, current.Generation)
		}
		if !seal.CreatedAt.Equal(current.CreatedAt) {
			return fmt.Errorf("escrow: replace seal %s: %w: a re-seal keeps the seal's creation instant",
				seal.ID, domain.ErrInvalidArgument)
		}

		moved, err := q.UpdateSealToNextGeneration(ctx, gen.UpdateSealToNextGenerationParams{
			Generation:        int64(seal.Generation),
			ThresholdRequired: int32(seal.Threshold.Required), //nolint:gosec // bounded by Threshold.Validate at 255
			ThresholdTotal:    int32(seal.Threshold.Total),    //nolint:gosec // bounded by Threshold.Validate at 255
			Commitment:        seal.Commitment[:],
			CheckInNs:         int64(seal.Liveness.CheckIn),
			GraceNs:           int64(seal.Liveness.Grace),
			LivenessSince:     seal.Liveness.Since,
			SealedAt:          seal.SealedAt,
			TenantID:          s.tenant.String(),
			SealID:            seal.ID.String(),
		})
		if err != nil {
			return fmt.Errorf("escrow: replace seal %s: %w", seal.ID, classify(err))
		}
		if moved != 1 {
			// Unreachable given the read above, which ran in this same
			// transaction — but the predicate is the optimistic check that
			// turns a future bug into a failed rotation rather than a
			// silently forked custody arrangement, so the zero case is an
			// error rather than an assumption.
			return fmt.Errorf("escrow: replace seal %s: %w: the generation moved underneath this rotation",
				seal.ID, domain.ErrInvalidArgument)
		}

		if err := q.DeleteCustodians(ctx, gen.DeleteCustodiansParams{
			TenantID: s.tenant.String(), SealID: seal.ID.String(),
		}); err != nil {
			return fmt.Errorf("escrow: replace seal %s: %w", seal.ID, classify(err))
		}
		if err := q.DeleteEscalations(ctx, gen.DeleteEscalationsParams{
			TenantID: s.tenant.String(), SealID: seal.ID.String(),
		}); err != nil {
			return fmt.Errorf("escrow: replace seal %s: %w", seal.ID, classify(err))
		}
		if err := s.writeArrangement(ctx, q, seal); err != nil {
			return err
		}

		// CHARTER.md's fourth safety property: the deployment's share of the
		// superseded generation goes with the generation. The row count is
		// ignored — a seal the deployment held no share of is an ordinary
		// case, not a failed rotation.
		if _, err := q.DeleteHeldShare(ctx, gen.DeleteHeldShareParams{
			TenantID: s.tenant.String(), SealID: seal.ID.String(),
		}); err != nil {
			return fmt.Errorf("escrow: replace seal %s: %w", seal.ID, classify(err))
		}
		return nil
	})
}

// HoldShare implements sealstore.SealStore.
func (s *store) HoldShare(ctx context.Context, share domain.Share) error {
	if err := share.Validate(); err != nil {
		return fmt.Errorf("escrow: hold share: %w", err)
	}

	return s.inTx(ctx, "hold share", func(q *gen.Queries) error {
		seal, err := s.readSeal(ctx, q, share.Seal())
		if err != nil {
			return err
		}
		if err := seal.AcceptsHeldShare(share); err != nil {
			return fmt.Errorf("escrow: hold share for seal %s: %w", seal.ID, err)
		}

		err = q.InsertHeldShare(ctx, gen.InsertHeldShareParams{
			TenantID:   s.tenant.String(),
			SealID:     share.Seal().String(),
			Generation: int64(share.Generation()),
			ShareIndex: int16(share.Index()),
			Material:   share.Material(),
		})
		switch {
		case err == nil:
			return nil
		case isUniqueViolation(err):
			// CHARTER.md's first safety property, enforced by the primary key
			// rather than by a read-then-insert — which is what makes it hold
			// against a concurrent transaction.
			return fmt.Errorf("escrow: hold share for seal %s: %w", share.Seal(), domain.ErrShareAlreadyHeld)
		default:
			return fmt.Errorf("escrow: hold share for seal %s: %w", share.Seal(), classify(err))
		}
	})
}

// HeldShare implements sealstore.SealStore.
func (s *store) HeldShare(ctx context.Context, id domain.SealID) (domain.Share, error) {
	var out domain.Share
	err := s.inTx(ctx, "read held share", func(q *gen.Queries) error {
		row, err := q.HeldShare(ctx, gen.HeldShareParams{TenantID: s.tenant.String(), SealID: id.String()})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("escrow: read held share for seal %s: %w", id, domain.ErrNoHeldShare)
		}
		if err != nil {
			return fmt.Errorf("escrow: read held share for seal %s: %w", id, classify(err))
		}

		generation, err := generationFrom(row.Generation)
		if err != nil {
			return fmt.Errorf("escrow: read held share for seal %s: %w", id, err)
		}
		index, err := shareIndexFrom(row.ShareIndex)
		if err != nil {
			return fmt.Errorf("escrow: read held share for seal %s: %w", id, err)
		}
		// Through the validating constructor, which copies the material and
		// rejects a wrong length rather than truncating. The error it may
		// return names the seal and the index and never the bytes.
		share, err := domain.NewShare(id, generation, index, row.Material)
		if err != nil {
			return fmt.Errorf("escrow: read held share for seal %s: %w", id, err)
		}
		out = share
		return nil
	})
	return out, err
}

// DiscardHeldShare implements sealstore.SealStore.
func (s *store) DiscardHeldShare(ctx context.Context, id domain.SealID) error {
	return s.inTx(ctx, "discard held share", func(q *gen.Queries) error {
		removed, err := q.DeleteHeldShare(ctx, gen.DeleteHeldShareParams{
			TenantID: s.tenant.String(), SealID: id.String(),
		})
		if err != nil {
			return fmt.Errorf("escrow: discard held share for seal %s: %w", id, classify(err))
		}
		if removed == 0 {
			return fmt.Errorf("escrow: discard held share for seal %s: %w", id, domain.ErrNoHeldShare)
		}
		return nil
	})
}

// RecordProofOfLife implements sealstore.SealStore.
func (s *store) RecordProofOfLife(ctx context.Context, proof domain.ProofOfLife) error {
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("escrow: record proof of life: %w", err)
	}

	return s.inTx(ctx, "record proof of life", func(q *gen.Queries) error {
		written, err := q.InsertProofOfLife(ctx, gen.InsertProofOfLifeParams{
			TenantID:   s.tenant.String(),
			SealID:     proof.Seal.String(),
			ProofID:    proof.ID.String(),
			ObservedAt: proof.At,
			Channel:    proof.Channel.String(),
		})
		if err != nil {
			if isForeignKeyViolation(err) {
				return fmt.Errorf("escrow: record proof of life for seal %s: %w", proof.Seal, domain.ErrSealNotFound)
			}
			return fmt.Errorf("escrow: record proof of life for seal %s: %w", proof.Seal, classify(err))
		}
		if written == 1 {
			return nil
		}

		// Zero rows means the id was already there. A redelivery of the same
		// proof is one proof and not an error; the same id carrying anything
		// different is a bug or a forgery and is refused rather than silently
		// resolved in favour of one of the two.
		row, err := q.ProofOfLife(ctx, gen.ProofOfLifeParams{
			TenantID: s.tenant.String(), SealID: proof.Seal.String(), ProofID: proof.ID.String(),
		})
		if err != nil {
			return fmt.Errorf("escrow: record proof of life %s: %w", proof.ID, classify(err))
		}
		stored := domain.ProofOfLife{
			Seal:    proof.Seal,
			ID:      proof.ID,
			At:      domain.CanonicalTime(row.ObservedAt),
			Channel: domain.ChannelID(row.Channel),
		}
		if stored.Equal(proof) {
			return nil
		}
		return fmt.Errorf("escrow: record proof of life %s for seal %s: %w: a proof with that id is already recorded with different content",
			proof.ID, proof.Seal, domain.ErrInvalidArgument)
	})
}

// ProofsOfLife implements sealstore.SealStore.
func (s *store) ProofsOfLife(ctx context.Context, id domain.SealID) ([]domain.ProofOfLife, error) {
	var out []domain.ProofOfLife
	err := s.inTx(ctx, "read proofs of life", func(q *gen.Queries) error {
		if err := s.requireSeal(ctx, q, id); err != nil {
			return err
		}
		rows, err := q.ProofsOfLife(ctx, gen.ProofsOfLifeParams{TenantID: s.tenant.String(), SealID: id.String()})
		if err != nil {
			return fmt.Errorf("escrow: read proofs of life for seal %s: %w", id, classify(err))
		}

		out = make([]domain.ProofOfLife, 0, len(rows))
		for _, row := range rows {
			proofID, err := domain.ParseProofID(row.ProofID)
			if err != nil {
				return fmt.Errorf("escrow: read proofs of life for seal %s: %w", id, err)
			}
			out = append(out, domain.ProofOfLife{
				Seal:    id,
				ID:      proofID,
				At:      domain.CanonicalTime(row.ObservedAt),
				Channel: domain.ChannelID(row.Channel),
			})
		}
		return nil
	})
	return out, err
}

// RecordCeremony implements sealstore.SealStore.
func (s *store) RecordCeremony(ctx context.Context, ceremony domain.Ceremony) error {
	if err := ceremony.Validate(); err != nil {
		return fmt.Errorf("escrow: record ceremony: %w", err)
	}
	if ceremony.Tenant != s.tenant {
		return fmt.Errorf("escrow: record ceremony: %w: ceremony belongs to another tenant", domain.ErrInvalidArgument)
	}

	return s.inTx(ctx, "record ceremony", func(q *gen.Queries) error {
		seal, err := s.readSeal(ctx, q, ceremony.Seal)
		if err != nil {
			return err
		}
		if ceremony.Generation > seal.Generation {
			return fmt.Errorf("escrow: record ceremony for seal %s: %w: ceremony is at %s, ahead of the seal's %s",
				ceremony.Seal, domain.ErrInvalidArgument, ceremony.Generation, seal.Generation)
		}

		written, err := q.InsertCeremony(ctx, gen.InsertCeremonyParams{
			TenantID:         s.tenant.String(),
			CeremonyID:       ceremony.ID.String(),
			SealID:           ceremony.Seal.String(),
			Generation:       int64(ceremony.Generation),
			ReleaseCondition: ceremony.Condition.String(),
			Effect:           ceremony.Effect.String(),
			Participants:     participantStrings(ceremony.Participants),
			SharesPresented:  int32(ceremony.SharesPresented), //nolint:gosec // bounded by Validate at MaxShares
			SharesRequired:   int32(ceremony.SharesRequired),  //nolint:gosec // bounded by Validate at MaxShares
			Outcome:          ceremony.Outcome.String(),
			Reason:           ceremony.Reason,
			ConcludedAt:      ceremony.At,
		})
		if err != nil {
			return fmt.Errorf("escrow: record ceremony %s: %w", ceremony.ID, classify(err))
		}
		if written == 1 {
			return nil
		}

		row, err := q.Ceremony(ctx, gen.CeremonyParams{
			TenantID: s.tenant.String(), CeremonyID: ceremony.ID.String(),
		})
		if err != nil {
			return fmt.Errorf("escrow: record ceremony %s: %w", ceremony.ID, classify(err))
		}
		stored, err := s.ceremonyFrom(ceremony.ID, row.SealID, row.Generation, row.ReleaseCondition, row.Effect,
			row.Participants, row.SharesPresented, row.SharesRequired, row.Outcome, row.Reason, row.ConcludedAt)
		if err != nil {
			return fmt.Errorf("escrow: record ceremony %s: %w", ceremony.ID, err)
		}
		if stored.Equal(ceremony) {
			return nil
		}
		return fmt.Errorf("escrow: record ceremony %s for seal %s: %w: a ceremony with that id is already recorded with different content",
			ceremony.ID, ceremony.Seal, domain.ErrInvalidArgument)
	})
}

// Ceremonies implements sealstore.SealStore.
func (s *store) Ceremonies(ctx context.Context, id domain.SealID) ([]domain.Ceremony, error) {
	var out []domain.Ceremony
	err := s.inTx(ctx, "read ceremonies", func(q *gen.Queries) error {
		if err := s.requireSeal(ctx, q, id); err != nil {
			return err
		}
		rows, err := q.Ceremonies(ctx, gen.CeremoniesParams{TenantID: s.tenant.String(), SealID: id.String()})
		if err != nil {
			return fmt.Errorf("escrow: read ceremonies for seal %s: %w", id, classify(err))
		}

		out = make([]domain.Ceremony, 0, len(rows))
		for _, row := range rows {
			ceremonyID, err := domain.ParseCeremonyID(row.CeremonyID)
			if err != nil {
				return fmt.Errorf("escrow: read ceremonies for seal %s: %w", id, err)
			}
			ceremony, err := s.ceremonyFrom(ceremonyID, id.String(), row.Generation, row.ReleaseCondition, row.Effect,
				row.Participants, row.SharesPresented, row.SharesRequired, row.Outcome, row.Reason, row.ConcludedAt)
			if err != nil {
				return fmt.Errorf("escrow: read ceremonies for seal %s: %w", id, err)
			}
			out = append(out, ceremony)
		}
		return nil
	})
	return out, err
}

// writeArrangement inserts a seal's custodian list and notification ladder.
// It is shared by CreateSeal and ReplaceSeal so that the two cannot drift on
// how an arrangement is written — in particular so that neither can write a
// ladder whose stage numbering disagrees with the other's.
func (s *store) writeArrangement(ctx context.Context, q *gen.Queries, seal domain.Seal) error {
	for _, c := range seal.Custodians {
		if err := q.InsertCustodian(ctx, gen.InsertCustodianParams{
			TenantID:    s.tenant.String(),
			SealID:      seal.ID.String(),
			CustodianID: c.ID.String(),
			Holder:      c.Holder.String(),
			ShareIndex:  int16(c.Index),
		}); err != nil {
			// The partial unique index on holder = 'system' and the unique
			// constraint on share_index both surface here, and both are
			// CHARTER.md property 1 or its corollary. domain.Seal.Validate
			// already refused these, so reaching this branch means something
			// bypassed it; it is reported as an argument error rather than as
			// storage, because it is.
			if isUniqueViolation(err) {
				return fmt.Errorf("escrow: seal %s: %w: the custodian list was refused by the schema's uniqueness constraints (a duplicate custodian, a duplicate share index, or a second share inside the deployment)",
					seal.ID, domain.ErrInvalidArgument)
			}
			return fmt.Errorf("escrow: seal %s: write custodian: %w", seal.ID, classify(err))
		}
	}

	for i, e := range seal.Liveness.Escalations {
		if err := q.InsertEscalation(ctx, gen.InsertEscalationParams{
			TenantID: s.tenant.String(),
			SealID:   seal.ID.String(),
			Stage:    int32(i + 1), //nolint:gosec // the ladder is bounded by the schedule a caller wrote
			AfterNs:  int64(e.After),
			Channel:  e.Channel.String(),
		}); err != nil {
			return fmt.Errorf("escrow: seal %s: write escalation: %w", seal.ID, classify(err))
		}
	}
	return nil
}

// readSeal assembles one seal from its three tables. They are read in one
// transaction because they are one value: a seal read with two of the three
// is not a seal.
func (s *store) readSeal(ctx context.Context, q *gen.Queries, id domain.SealID) (domain.Seal, error) {
	row, err := q.Seal(ctx, gen.SealParams{TenantID: s.tenant.String(), SealID: id.String()})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, domain.ErrSealNotFound)
	}
	if err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, classify(err))
	}

	generation, err := generationFrom(row.Generation)
	if err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, err)
	}
	commitment, err := domain.KeyCommitmentFrom(row.Commitment)
	if err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, err)
	}

	custodianRows, err := q.Custodians(ctx, gen.CustodiansParams{TenantID: s.tenant.String(), SealID: id.String()})
	if err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, classify(err))
	}
	custodians := make([]domain.Custodian, 0, len(custodianRows))
	for _, c := range custodianRows {
		custodianID, err := domain.ParseCustodianID(c.CustodianID)
		if err != nil {
			return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, err)
		}
		index, err := shareIndexFrom(c.ShareIndex)
		if err != nil {
			return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, err)
		}
		custodians = append(custodians, domain.Custodian{
			ID: custodianID, Holder: domain.HolderKind(c.Holder), Index: index,
		})
	}

	escalationRows, err := q.Escalations(ctx, gen.EscalationsParams{TenantID: s.tenant.String(), SealID: id.String()})
	if err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, classify(err))
	}
	escalations := make([]domain.Escalation, 0, len(escalationRows))
	for _, e := range escalationRows {
		escalations = append(escalations, domain.Escalation{
			After: durationFrom(e.AfterNs), Channel: domain.ChannelID(e.Channel),
		})
	}

	seal := domain.Seal{
		Tenant:     s.tenant,
		ID:         id,
		Generation: generation,
		Threshold:  domain.Threshold{Required: int(row.ThresholdRequired), Total: int(row.ThresholdTotal)},
		Commitment: commitment,
		Custodians: custodians,
		Liveness: domain.LivenessSchedule{
			Since:       domain.CanonicalTime(row.LivenessSince),
			CheckIn:     durationFrom(row.CheckInNs),
			Escalations: escalations,
			Grace:       durationFrom(row.GraceNs),
		},
		CreatedAt: domain.CanonicalTime(row.CreatedAt),
		SealedAt:  domain.CanonicalTime(row.SealedAt),
	}
	// Validated on the way out as well as on the way in. A stored seal that
	// no longer satisfies the invariants — because somebody wrote to the
	// tables by hand, or because a constraint was dropped — must be a refusal
	// rather than a value that reaches a ceremony.
	if err := seal.Validate(); err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, err)
	}
	return seal, nil
}

// requireSeal reports whether the seal exists, for the read paths that need
// to distinguish "no proofs" from "no seal". It reads only the seal's own row,
// not its arrangement.
func (s *store) requireSeal(ctx context.Context, q *gen.Queries, id domain.SealID) error {
	_, err := q.Seal(ctx, gen.SealParams{TenantID: s.tenant.String(), SealID: id.String()})
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("escrow: seal %s: %w", id, domain.ErrSealNotFound)
	}
	if err != nil {
		return fmt.Errorf("escrow: seal %s: %w", id, classify(err))
	}
	return nil
}

// ceremonyFrom assembles a domain.Ceremony out of the columns both ceremony
// queries return. The two call sites return different generated row types for
// the same row, so the conversion takes the columns rather than either struct.
func (s *store) ceremonyFrom(
	id domain.CeremonyID, sealID string, generation int64, condition, effect string,
	participants []string, presented, required int32, outcome, reason string, at time.Time,
) (domain.Ceremony, error) {
	seal, err := domain.ParseSealID(sealID)
	if err != nil {
		return domain.Ceremony{}, err
	}
	gener, err := generationFrom(generation)
	if err != nil {
		return domain.Ceremony{}, err
	}
	ids := make([]domain.CustodianID, 0, len(participants))
	for _, p := range participants {
		custodianID, err := domain.ParseCustodianID(p)
		if err != nil {
			return domain.Ceremony{}, err
		}
		ids = append(ids, custodianID)
	}
	return domain.Ceremony{
		Tenant:          s.tenant,
		ID:              id,
		Seal:            seal,
		Generation:      gener,
		Condition:       domain.ReleaseConditionKind(condition),
		Effect:          domain.ReleaseEffect(effect),
		Participants:    ids,
		SharesPresented: int(presented),
		SharesRequired:  int(required),
		Outcome:         domain.CeremonyOutcome(outcome),
		Reason:          reason,
		At:              domain.CanonicalTime(at),
	}, nil
}

// participantStrings renders a ceremony's participants for the text[] column.
func participantStrings(ids []domain.CustodianID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// inTx runs fn inside a transaction this adapter opens, having narrowed into
// the application role and established the store's tenant as the
// row-level-security context. See this package's doc comment for why every
// operation — reads included — goes through here.
func (s *store) inTx(ctx context.Context, op string, fn func(q *gen.Queries) error) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: %s: %w", op, err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("escrow: %s: %w: begin: %w", op, domain.ErrUnavailable, err)
	}
	// Rolled back unconditionally on the way out; a commit makes the rollback
	// a no-op. A named error from the rollback is deliberately discarded:
	// there is nothing a caller can do with it that is better than the error
	// that caused the rollback.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.scope(ctx, tx); err != nil {
		return fmt.Errorf("escrow: %s: %w", op, err)
	}
	if err := fn(s.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("escrow: %s: %w: commit: %w", op, classify(err), err)
	}
	return nil
}

// scope narrows tx into the application role and sets the tenant context.
//
// SET LOCAL ROLE is composed as SQL text because a role name cannot be a
// bound parameter; it is validated as a plain identifier at Open and quoted
// with pgx.Identifier.Sanitize here. The tenant, by contrast, *is* a bound
// parameter — set_config is an ordinary function call, so the one value that
// comes from a caller never reaches Postgres as SQL text.
//
// Both are transaction-scoped (SET LOCAL, and set_config's third argument
// true), so neither can leak across a reused pooled connection.
func (s *store) scope(ctx context.Context, tx pgx.Tx) error {
	if s.appRole != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{s.appRole}.Sanitize()); err != nil {
			return fmt.Errorf("%w: narrow into role %s: %w", domain.ErrInvalidConfig, s.appRole, err)
		}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", tenantGUC, s.tenant.String()); err != nil {
		return fmt.Errorf("%w: establish the tenant context: %w", classify(err), err)
	}
	return nil
}

// generationFrom converts a bigint column to a domain.Generation, rejecting a
// value outside the type's range rather than truncating it. A truncated
// generation would make a current share look superseded, or a superseded one
// look current, which is the pair of mistakes CHARTER.md's fourth property
// exists to prevent.
func generationFrom(v int64) (domain.Generation, error) {
	if v < int64(domain.FirstGeneration) || v > math.MaxUint32 {
		return 0, fmt.Errorf("%w: stored generation %d is outside the representable range", domain.ErrStorage, v)
	}
	return domain.Generation(v), nil
}

// shareIndexFrom converts a smallint column to a domain.ShareIndex, rejecting
// zero and anything above 255 rather than truncating. Index 0 is the secret
// itself, so a truncation to zero would be the worst possible silent error.
func shareIndexFrom(v int16) (domain.ShareIndex, error) {
	if v < 1 || v > domain.MaxShares {
		return 0, fmt.Errorf("%w: stored share index %d is outside 1..%d", domain.ErrStorage, v, domain.MaxShares)
	}
	return domain.ShareIndex(v), nil
}

// durationFrom converts a bigint nanosecond column to a time.Duration. A Go
// Duration is an int64 nanosecond count, so this is exact by construction —
// which is why the schema stores nanoseconds rather than an interval.
func durationFrom(ns int64) time.Duration { return time.Duration(ns) }

// isUniqueViolation reports whether err is Postgres refusing a duplicate key
// (SQLSTATE 23505). It is what carries CHARTER.md's first safety property
// from the schema into this module's sentinels.
func isUniqueViolation(err error) bool { return hasSQLState(err, "23505") }

// isForeignKeyViolation reports whether err is Postgres refusing a row whose
// parent does not exist (SQLSTATE 23503), which here always means the seal is
// not stored.
func isForeignKeyViolation(err error) bool { return hasSQLState(err, "23503") }

func hasSQLState(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// classify maps a Postgres error onto this module's taxonomy **without
// carrying the database's own message text.**
//
// That omission is the point rather than terseness. escrow.held_share.material
// holds real share bytes, and Postgres echoes offending values into some of
// its messages — a check violation, a failed cast — so forwarding the message
// would put share material into an error string on exactly the paths most
// likely to be logged. The SQLSTATE is enough to choose a sentinel, and the
// caller already holds the seal and the index that the error names.
//
// Migration errors are the deliberate exception and live in internal/migrate:
// they are about DDL rather than rows, nothing in them has seen a share, and
// an operator needs to know what Postgres actually objected to.
func classify(err error) error {
	var connectErr *pgconn.ConnectError
	if errors.As(err, &connectErr) {
		return domain.ErrUnavailable
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return err
		default:
			return domain.ErrStorage
		}
	}

	switch pgErr.Code {
	case "23505": // unique_violation
		return domain.ErrSealExists
	case "23503": // foreign_key_violation
		return domain.ErrSealNotFound
	case "23502", "23514": // not_null_violation, check_violation
		return domain.ErrInvalidArgument
	case "40001", "40P01", "55P03", "57014": // serialization_failure, deadlock_detected, lock_not_available, query_canceled
		return domain.ErrUnavailable
	case "08000", "08003", "08006", "08001", "08004": // connection_exception and friends
		return domain.ErrUnavailable
	default:
		return domain.ErrStorage
	}
}

// isPlainIdentifier reports whether s is safe to use as an unquoted-shaped SQL
// identifier. Duplicated from internal/migrate rather than shared, because the
// two packages are on opposite sides of this module's one dependency on goose
// and a consumer opening a store should not link a migration engine.
func isPlainIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return len(s) > 0
}
