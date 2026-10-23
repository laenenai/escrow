// Package migrate applies this module's embedded schema and reports on its
// state. It is the only package that imports goose; callers see Up, Status,
// Applied and Config.
//
// # A schema per module, with its own version table
//
// These tables live in the *consumer's* database, next to that consumer's own
// schema and its own goose sequence. Two independent migration owners writing
// one database collide on goose's single version table, so each shared module
// owns a Postgres schema and keeps its version table inside it: this one owns
// schema "escrow" and records its state in escrow.goose_db_version.
// Independent sequences, no shared ordering, no collision.
//
// The schema is created by Up itself, before goose runs, rather than only by
// migration 00001: goose has to create its bookkeeping table before any
// migration has run, and that table lives in the schema, so the schema has to
// exist first.
//
// # What Up applies, in two layers
//
// Which layer a piece of DDL belongs in is decided by one question: can a
// later deployment legitimately change it?
//
//  1. **The fixed schema**, as goose migrations (db/migrations/*.sql): the
//     tables, the constraints, the indexes. Versioned, applied once, never
//     changed.
//  2. **The row-level-security policies and the application role's grants**,
//     reconciled on every Up. The role's name is configuration, so the GRANT
//     has to be composed at run time; and the policies are reconciled rather
//     than versioned for a reason that is a security finding rather than a
//     preference — see enforce.go.
//
// Layer 2 is deliberately not a versioned migration. A versioned migration
// records itself as applied, so a deployment whose policies had been weakened
// or whose application role had been renamed would come up with no isolation
// and no grants at all, while goose reported everything applied. Reconciling
// instead means the state of the database is a function of the configuration
// rather than of the order in which configurations were tried.
//
// # Why there is no sqlc in this package
//
// CONVENTIONS.md makes sqlc the default and names one exception: SQL composed
// at run time. Layer 2 is entirely that exception — a role name from
// Config.AppRole, and tenancy.EnableRLS composing policy DDL from a table
// list. Every identifier goes through pgx.Identifier.Sanitize, and the whole
// set of grants is one list in enforce.go rather than assembled across
// methods, which is what the exception asks for. db/migrations is nonetheless
// the schema sqlc generates internal/pgstore's queries against, so the
// migrations this package applies are what keep those queries honest: a
// column renamed here and not there is a generation failure rather than a
// run-time one.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/laenenai/escrow/db/migrations"
	"github.com/laenenai/escrow/internal/domain"
)

// Schema is the Postgres schema this module owns. Nothing this module creates
// lives outside it.
const Schema = "escrow"

// versionTableName is where goose records which of this module's migrations
// have been applied: inside this module's own schema, which is the whole
// point — see the package doc comment.
const versionTableName = Schema + ".goose_db_version"

// lockKey is the Postgres advisory lock key Up and Status take for the
// duration of their run, so that N processes starting against the same
// database serialize their migration attempts instead of racing. It is the
// CRC32 (IEEE) checksum of this package's import path — specific to this
// module, and vanishingly unlikely to collide with a lock taken by anything
// else sharing the same cluster, including the consumer's own migrations:
//
//	crc32.ChecksumIEEE([]byte("github.com/laenenai/escrow/internal/migrate"))
//
// It must never change: changing it would let an old and a new binary migrate
// concurrently against each other during a rolling deploy, which is the race
// it exists to prevent. That it differs from every other module's key is the
// point — two modules migrating two schemas in one database have no reason to
// wait for each other.
const lockKey int64 = 3046141600

// lockPollPeriodSeconds and lockMaxRetries bound how long Up and Status wait
// for the advisory lock before giving up as domain.ErrUnavailable. goose's
// session locker polls pg_try_advisory_lock rather than blocking, so these are
// the poll interval in whole seconds (1 is the library's minimum) and the
// number of retries after the first attempt — about five minutes.
var (
	lockPollPeriodSeconds uint64 = 1
	lockMaxRetries        uint64 = 300
)

// Applied describes one migration's state as goose's bookkeeping table knows
// it, for an operator-facing status command to print.
type Applied struct {
	// Version is the migration's leading version number, e.g. 1 for
	// 00001_escrow.sql.
	Version int64
	// Name is the migration's filename, e.g. "00001_escrow.sql".
	Name string
	// Applied reports whether this migration has been applied. AppliedAt is
	// the zero time when it has not.
	Applied   bool
	AppliedAt time.Time
}

// Config configures Up.
type Config struct {
	// AppRole is the name of the Postgres role the application runs as at
	// run time: the role that is granted this schema's tables and that
	// row-level security is therefore meaningful for. Required.
	//
	// It is configuration rather than a constant because the GRANT has to
	// name it and the role is the deployment's to name. There is deliberately
	// no default: a default would be a role name nobody chose, which the
	// policies would then appear to have been applied for while the
	// application connected as something else.
	//
	// Up creates the role if it does not exist, as NOLOGIN — nothing connects
	// as it directly; a session reaches it through SET ROLE, which is what
	// keeps the single-connection-string deployment model available. The role
	// is created NOBYPASSRLS, because a role that bypasses row-level security
	// makes every policy in this schema decorative.
	AppRole string
}

// resolve validates cfg.
func (c Config) resolve() (Config, error) {
	if c.AppRole == "" {
		return Config{}, fmt.Errorf("%w: migrate: AppRole is required: it is the role the GRANT names and the role row-level security is enforced for, and there is no sensible default for it",
			domain.ErrInvalidConfig)
	}
	if !isPlainIdentifier(c.AppRole) {
		return Config{}, fmt.Errorf("%w: migrate: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit",
			domain.ErrInvalidConfig, c.AppRole)
	}
	return c, nil
}

// Up applies this module's schema to pool: the fixed migrations, then the
// policies and the grants. See the package doc comment for why those are two
// layers rather than one.
//
// pool must connect as a role that can create objects in — and ideally owns —
// schema "escrow", and that can GRANT to cfg.AppRole and create a role. That
// is the migration identity, and it is deliberately not the identity the
// application runs as: `SET ROLE` is reversible with `RESET ROLE`, so a single
// owner connection switching roles makes the separation per-session and
// dependent on every path remembering to set it. Open the migration pool,
// migrate, close it; a long-lived owner pool in the process is a standing
// escalation target for no benefit, since migration is a startup activity.
//
// Calling it again is safe and expected: it applies nothing already applied,
// and it re-asserts the policies and the grants — which is how a policy whose
// predicate has drifted gets repaired.
func Up(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	resolved, err := cfg.resolve()
	if err != nil {
		return err
	}
	if pool == nil {
		return fmt.Errorf("%w: migrate: a pool is required", domain.ErrInvalidConfig)
	}

	if err := ensureSchema(ctx, pool); err != nil {
		return err
	}

	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return err
	}
	defer closeDB()

	if _, err := provider.Up(ctx); err != nil {
		return classify("apply migrations", err)
	}

	return reconcile(ctx, pool, resolved)
}

// Status reports the state of every embedded migration: applied ones with the
// time they were applied, and pending ones not yet run.
//
// It reports only layer 1, the versioned migrations. Layer 2 has no "pending"
// state to report: it is reconciled on every Up, so the question "are the
// policies in place" is answered by asking the catalog — through
// tenancy.AssertRLSCoverage — rather than by a version number.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]Applied, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: migrate: a pool is required", domain.ErrInvalidConfig)
	}
	if err := ensureSchema(ctx, pool); err != nil {
		return nil, err
	}

	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	statuses, err := provider.Status(ctx)
	if err != nil {
		return nil, classify("status", err)
	}

	applied := make([]Applied, 0, len(statuses))
	for _, s := range statuses {
		applied = append(applied, Applied{
			Version:   s.Source.Version,
			Name:      path.Base(s.Source.Path),
			Applied:   s.State == goose.StateApplied,
			AppliedAt: s.AppliedAt,
		})
	}
	return applied, nil
}

// reconcile applies layer 2 inside one transaction holding the same advisory
// lock goose used for layer 1, so the whole of Up is serialized against
// another process doing the same thing. DDL is transactional in Postgres, so a
// failure anywhere in here leaves the database exactly as the migrations left
// it rather than half-secured — which matters more than usual, because a table
// left FORCEd into row security with no policy denies every command against it
// for every role, including the owner, until somebody fixes it by hand.
func reconcile(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: migrate: begin reconciliation: %w", domain.ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// pg_advisory_xact_lock blocks rather than polling and is released by the
	// commit or the rollback, which is the right shape here: the transaction
	// is short and there is nothing useful to do while waiting.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("%w: migrate: take reconciliation lock: %w", domain.ErrUnavailable, err)
	}

	if err := ensureAppRole(ctx, tx, cfg.AppRole); err != nil {
		return err
	}
	if err := grantToAppRole(ctx, tx, cfg.AppRole); err != nil {
		return err
	}
	if err := enableTenantIsolation(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: migrate: commit reconciliation: %w", domain.ErrUnavailable, err)
	}
	return nil
}

// ensureSchema creates this module's schema if it is not there yet, because
// goose's version table lives inside it and goose has to create that table
// before it can run the migration that would otherwise create the schema.
//
// CREATE SCHEMA IF NOT EXISTS still loses a race against a concurrent
// identical statement — both sessions can see "not there" before either
// commits — so duplicate_schema is caught and treated as success.
func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{Schema}.Sanitize())
	switch {
	case err == nil, isDuplicateObject(err):
		return nil
	default:
		return classify("create schema "+Schema, err)
	}
}

// newProvider builds a goose Provider wrapping pool, configured with the
// session-level advisory lock described on lockKey, plus a cleanup function
// that closes the *sql.DB wrapper it created — not pool itself, which pgx
// documents stdlib.OpenDBFromPool as never closing.
//
// goose checks out exactly one *sql.Conn from db for any one call to Up or
// Status and runs the session lock, the bookkeeping check and every migration
// statement on that same connection. That is what makes a session-scoped
// advisory lock actually serialize the work it is held around.
func newProvider(pool *pgxpool.Pool) (*goose.Provider, func(), error) {
	db := stdlib.OpenDBFromPool(pool)
	closeDB := func() { _ = db.Close() }

	provider, err := buildProvider(db)
	if err != nil {
		closeDB()
		return nil, nil, err
	}
	return provider, closeDB, nil
}

func buildProvider(db *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockID(lockKey),
		lock.WithLockTimeout(lockPollPeriodSeconds, lockMaxRetries),
	)
	if err != nil {
		// Only reachable if the fixed arguments above were invalid, which is a
		// defect in this binary rather than a runtime condition.
		return nil, fmt.Errorf("%w: migrate: build session locker: %w", domain.ErrInvalidConfig, err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithSessionLocker(locker),
		goose.WithTableName(versionTableName),
	)
	if err != nil {
		// Reachable if the embedded migration set is malformed — again a defect
		// in the binary rather than in the database.
		return nil, fmt.Errorf("%w: migrate: build goose provider: %w", domain.ErrInvalidConfig, err)
	}
	return provider, nil
}

// classify maps an error out of goose or pgx onto this module's taxonomy, so
// nothing in this package returns a bare driver error across its boundary.
//
// Two failure modes are "reachable in principle, just not right now", and
// therefore domain.ErrUnavailable — worth a caller retrying: the database
// could not be reached at all, which pgx reports as a *pgconn.ConnectError
// anywhere in the chain; and the advisory lock could not be acquired within
// its budget, meaning another process is still migrating. goose exports no
// sentinel for the latter — its exhausted-retries error is the fixed,
// unexported string "failed to acquire lock", which is what is matched below,
// pinned to the goose version in go.mod.
//
// Everything else means the binary's embedded schema does not fit this
// database, which is a deployment defect, so domain.ErrInvalidConfig. The
// underlying error stays wrapped either way: unlike the adapter's row paths,
// nothing here has seen a share, so an operator gets to read what Postgres
// actually said.
func classify(op string, err error) error {
	var connectErr *pgconn.ConnectError
	switch {
	case errors.As(err, &connectErr):
		return fmt.Errorf("%w: migrate: %s: could not reach the database: %w", domain.ErrUnavailable, op, err)
	case strings.Contains(err.Error(), "failed to acquire lock"):
		return fmt.Errorf("%w: migrate: %s: timed out waiting for another migration to finish: %w", domain.ErrUnavailable, op, err)
	default:
		return fmt.Errorf("%w: migrate: %s: %w", domain.ErrInvalidConfig, op, err)
	}
}

// isDuplicateObject reports whether err is Postgres complaining that
// something we asked it to create already exists. Every CREATE in the
// reconciliation layer is idempotent by intent, and the IF NOT EXISTS form
// still loses a race against a concurrent identical statement, so these codes
// are success rather than failure.
func isDuplicateObject(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "42P06", // duplicate_schema
		"42P07", // duplicate_table
		"42710", // duplicate_object (a role, a policy)
		"23505": // unique_violation, which is how a lost CREATE ROLE race surfaces
		return true
	default:
		return false
	}
}

// isPlainIdentifier reports whether s is safe to use as an unquoted-shaped SQL
// identifier: ASCII letters, digits and underscore, not starting with a digit,
// and not empty.
//
// Every identifier this package interpolates also goes through
// pgx.Identifier.Sanitize, which quotes and escapes it; this check is a
// second, narrower gate in front of that, applied to the one identifier that
// comes from configuration. GRANT and CREATE ROLE cannot take a role name as a
// bound parameter, so the role name is the one value here that has to reach
// Postgres as SQL text, and a value in that position gets more than one reason
// to be safe.
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
