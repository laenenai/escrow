package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/laenenai/tenancy"
	"github.com/laenenai/tenancy/testdb"

	"github.com/laenenai/escrow"
	"github.com/laenenai/escrow/escrowtest"
	"github.com/laenenai/escrow/internal/migrate"
)

// appRole is the non-superuser role every assertion in this file runs as.
//
// It matters more here than in most adapters' tests, and the reason is worth
// repeating because it is the way a row-level-security test passes while
// proving nothing: **the container's default role is a superuser, and a
// superuser bypasses row security unconditionally** — FORCE ROW LEVEL
// SECURITY does not change that. So a test that ran its statements straight
// on testdb's pool would see every row of every tenant and report success. The
// store is therefore always opened with AppRole set, which makes it narrow
// into this role with SET LOCAL ROLE inside every transaction it opens, and
// the raw-SQL assertions below do the same narrowing by hand.
//
// It is a fixed, test-only name rather than a per-test one because roles are
// cluster-wide while one container serves the whole run, and there is nothing
// a test can learn from a unique role name that it cannot learn from a unique
// tenant.
const appRole = "escrow_app_test"

// TestPostgresStoreConformance runs the whole SealStore contract against the
// Postgres adapter.
//
// One database is created and migrated for the whole test, and each subtest
// gets a **fresh tenant** rather than a fresh database. That is deliberate on
// two counts: it is far cheaper than migrating once per subtest, and it means
// every subtest's isolation is the real mechanism — row-level security keyed
// on the tenant — rather than a separate database standing in for it. A
// subtest that saw another subtest's rows would be a cross-tenant disclosure,
// which is exactly the failure worth detecting.
func TestPostgresStoreConformance(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)

	var n atomic.Int64
	escrowtest.RunSealStoreSuite(t, func(t *testing.T) escrowtest.Deployment {
		tenant := freshTenant(t, &n)
		store, err := escrow.Open(context.Background(), escrow.Config{
			DB:      pool,
			Tenant:  tenant,
			AppRole: appRole,
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return escrowtest.Deployment{Store: store, Tenant: tenant}
	})
}

// TestASecondHeldShareIsNotARepresentableState is CHARTER.md's first safety
// property proved at the level the conformance suite cannot reach.
//
// The suite proves that HoldShare refuses a second share. That is the
// *contract*, and an adapter could satisfy it with a read-then-insert in Go
// that two concurrent transactions would both pass. This test asserts the
// *enforcement*: a second row for one seal is refused by
// escrow.held_share's primary key, by Postgres, against a raw INSERT issued
// by the owner role with no application code involved at all.
func TestASecondHeldShareIsNotARepresentableState(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)
	ctx := context.Background()
	var n atomic.Int64
	tenant := freshTenant(t, &n)

	store, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: tenant, AppRole: appRole})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seal, key, shares := createSeal(t, tenant, 3, 5)
	defer destroyAll(key, shares)
	if err := store.CreateSeal(ctx, seal); err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}
	mine, others := systemShare(t, seal, shares)
	if err := store.HoldShare(ctx, mine); err != nil {
		t.Fatalf("HoldShare: %v", err)
	}

	// As the owner, bypassing every line of Go in this module.
	_, err = pool.Exec(ctx,
		`INSERT INTO escrow.held_share (tenant_id, seal_id, generation, share_index, material)
		 VALUES ($1, $2, $3, $4, $5)`,
		tenant.String(), seal.ID.String(), int64(seal.Generation), int16(others[0].Index()), others[0].Material())
	if err == nil {
		t.Fatal("Postgres accepted a second held share for one seal: " +
			"escrow.held_share's primary key must be (tenant_id, seal_id), so that CHARTER.md's " +
			"first safety property is not a representable violation")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("the second insert failed with %v, want a unique violation (23505)", err)
	}

	var held int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM escrow.held_share WHERE tenant_id = $1 AND seal_id = $2",
		tenant.String(), seal.ID.String()).Scan(&held); err != nil {
		t.Fatalf("count held shares: %v", err)
	}
	if held != 1 {
		t.Fatalf("%d held shares exist for one seal, want 1", held)
	}
}

// TestASecondSystemCustodianIsNotARepresentableState is the corollary: the
// partial unique index on (tenant_id, seal_id) WHERE holder = 'system' is
// what stops a seal existing with two shares inside the deployment, which
// would make the deployment two steps closer to opening it alone.
func TestASecondSystemCustodianIsNotARepresentableState(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)
	ctx := context.Background()
	var n atomic.Int64
	tenant := freshTenant(t, &n)

	store, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: tenant, AppRole: appRole})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seal, key, shares := createSeal(t, tenant, 3, 5)
	defer destroyAll(key, shares)
	if err := store.CreateSeal(ctx, seal); err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}

	// Promote an external custodian to a system holder, as the owner.
	_, err = pool.Exec(ctx,
		`UPDATE escrow.custodian SET holder = 'system'
		 WHERE tenant_id = $1 AND seal_id = $2 AND holder = 'external'`,
		tenant.String(), seal.ID.String())
	if err == nil {
		t.Fatal("Postgres accepted a second custodian inside the deployment: " +
			"the partial unique index custodian_one_system_holder_per_seal must refuse it")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("the promotion failed with %v, want a unique violation (23505)", err)
	}
}

// TestRLSDeniesWithoutTenantContext is tenancy's central claim as it applies
// to this schema: a statement that forgets its tenant predicate returns
// nothing rather than another tenant's rows, **and does not raise**.
//
// Both halves are asserted. A test that passed while the statement errored
// would be testing that something went wrong rather than that the backstop
// quietly filtered everything — and the no-raise half is the reason tenancy's
// predicate uses nullif and takes no cast: current_setting(..., true) returns
// the empty string, not NULL, once any transaction on the connection has
// touched the setting, so a cast would raise for a caller with no tenant
// context instead of evaluating to false.
func TestRLSDeniesWithoutTenantContext(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)
	ctx := context.Background()
	var n atomic.Int64
	tenant := freshTenant(t, &n)

	store, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: tenant, AppRole: appRole})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seal, key, shares := createSeal(t, tenant, 2, 3)
	defer destroyAll(key, shares)
	if err := store.CreateSeal(ctx, seal); err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}

	for _, table := range migrate.Tables {
		t.Run(table, func(t *testing.T) {
			var count int
			err := asAppRole(ctx, t, pool, "", func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count)
			})
			if err != nil {
				t.Fatalf("counting %s with no tenant context raised %v, want zero rows and no error", table, err)
			}
			if count != 0 {
				t.Fatalf("%s returned %d rows with no tenant context, want 0: row-level security did not fail closed",
					table, count)
			}
		})
	}

	// With the context set, the same role sees exactly its own rows — which is
	// what makes the zero above a filter rather than a broken grant.
	var count int
	if err := asAppRole(ctx, t, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM escrow.seal").Scan(&count)
	}); err != nil {
		t.Fatalf("counting as the tenant: %v", err)
	}
	if count != 1 {
		t.Fatalf("the tenant sees %d of its own seals, want 1: the zero above was a missing grant, not a filter", count)
	}
}

// TestRLSAnAddedPermissivePolicyCannotWidenAccess is the regression test for a
// cross-tenant disclosure found in this project on 2026-10-23, carried into
// this module's schema because this module's tables are the ones whose
// disclosure would be unrecoverable.
//
// Postgres ORs permissive policies together and ANDs restrictive ones over the
// result. A tenant predicate written as a single `AS PERMISSIVE` policy is
// therefore OR-able away by **any** additional permissive policy on the same
// table — something any table owner can do, for instance to add a reporting
// view. Measured on Postgres 18.6 against that arrangement: a tenant seeing
// its own single row saw two the moment a second permissive policy existed,
// and the second row belonged to another tenant.
//
// So this test adds exactly such a policy and requires the tenant to keep
// seeing only its own rows. It fails against a permissive-only tenant policy
// and passes against the restrictive-plus-companion pair tenancy.EnableRLS
// installs — which is why internal/migrate calls that rather than writing
// policies by hand. tenancytest carries the same assertion for the module
// that owns the mechanism.
func TestRLSAnAddedPermissivePolicyCannotWidenAccess(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)
	ctx := context.Background()
	var n atomic.Int64
	mine, theirs := freshTenant(t, &n), freshTenant(t, &n)

	for _, tenant := range []escrow.TenantID{mine, theirs} {
		store, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: tenant, AppRole: appRole})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		seal, key, shares := createSeal(t, tenant, 2, 3)
		defer destroyAll(key, shares)
		if err := store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal for %s: %v", tenant, err)
		}
	}

	// The policy this test exists to defeat. A consumer adding a reporting or
	// admin view would write exactly this.
	if _, err := pool.Exec(ctx,
		"CREATE POLICY widen_attempt ON escrow.seal AS PERMISSIVE USING (true)"); err != nil {
		t.Fatalf("could not add the permissive policy this test exists to defeat: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP POLICY IF EXISTS widen_attempt ON escrow.seal")
	})

	var count int
	if err := asAppRole(ctx, t, pool, mine.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM escrow.seal").Scan(&count)
	}); err != nil {
		t.Fatalf("counting as the tenant: %v", err)
	}
	if count != 1 {
		t.Fatalf("with one extra permissive policy present, the tenant sees %d seals, want 1.\n"+
			"the tenant predicate was OR-ed away rather than AND-ed: it must be AS RESTRICTIVE, "+
			"with a permissive companion for it to AND against — which is what tenancy.EnableRLS installs "+
			"and why internal/migrate calls it rather than writing policies here", count)
	}

	// And a cross-tenant write is still refused, which is the half only
	// WITH CHECK covers: USING filters what a statement can see, so it makes a
	// cross-tenant SELECT, UPDATE or DELETE affect zero rows, but only
	// WITH CHECK stops an INSERT writing a row for another tenant.
	err := asAppRole(ctx, t, pool, mine.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO escrow.seal (tenant_id, seal_id, generation, threshold_required,
			     threshold_total, commitment, check_in_ns, grace_ns, liveness_since, created_at, sealed_at)
			 VALUES ($1, $2, 1, 2, 3, $3, 1, 1, now(), now(), now())`,
			theirs.String(), "00000000000000000000000000000abc", make([]byte, 32))
		return err
	})
	if err == nil {
		t.Fatal("a tenant inserted a seal for another tenant: the policy's WITH CHECK is missing or widened")
	}
	if !tenancy.IsRLSViolation(err) {
		t.Fatalf("the cross-tenant insert failed with %v, want a row-level-security violation", err)
	}
}

// TestCrossTenantReadsFindNothing is the same isolation asserted through this
// module's own API rather than through raw SQL: a store opened for one tenant
// cannot see another tenant's seal, and the sentinel it returns does not
// distinguish "no such seal" from "not yours" — a caller that could tell those
// apart could enumerate another tenant's seal ids by asking.
func TestCrossTenantReadsFindNothing(t *testing.T) {
	t.Parallel()

	pool := migratedPool(t)
	ctx := context.Background()
	var n atomic.Int64
	mine, theirs := freshTenant(t, &n), freshTenant(t, &n)

	ours, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: mine, AppRole: appRole})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seal, key, shares := createSeal(t, mine, 2, 3)
	defer destroyAll(key, shares)
	if err := ours.CreateSeal(ctx, seal); err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}
	theirStore, err := escrow.Open(ctx, escrow.Config{DB: pool, Tenant: theirs, AppRole: appRole})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := theirStore.Seal(ctx, seal.ID); !errors.Is(err, escrow.ErrSealNotFound) {
		t.Fatalf("another tenant's Seal error = %v, want ErrSealNotFound", err)
	}
	if _, err := theirStore.ProofsOfLife(ctx, seal.ID); !errors.Is(err, escrow.ErrSealNotFound) {
		t.Fatalf("another tenant's ProofsOfLife error = %v, want ErrSealNotFound", err)
	}
	if _, err := theirStore.HeldShare(ctx, seal.ID); !errors.Is(err, escrow.ErrNoHeldShare) &&
		!errors.Is(err, escrow.ErrSealNotFound) {
		t.Fatalf("another tenant's HeldShare error = %v, want ErrNoHeldShare or ErrSealNotFound", err)
	}

	// A tenant that creates a seal with the same id is creating its own seal,
	// not colliding with somebody else's — which is what makes tenant_id part
	// of the primary key rather than a filter.
	theirSeal := seal.Clone()
	theirSeal.Tenant = theirs
	if err := theirStore.CreateSeal(ctx, theirSeal); err != nil {
		t.Fatalf("another tenant creating a seal with the same id: %v", err)
	}
}

// TestMigrateIsIdempotentAndRepairs covers the reason the policies and grants
// are reconciled on every Up rather than written into the versioned migration:
// a migration that has already been applied is never re-run, so a policy
// weakened or dropped afterwards would stay that way while goose reported
// everything applied.
func TestMigrateIsIdempotentAndRepairs(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(migrator))
	ctx := context.Background()

	// A second Up must be a no-op rather than a failure.
	if err := escrow.Migrate(ctx, db.Pool(), escrow.MigrateConfig{AppRole: appRole}); err != nil {
		t.Fatalf("a second Migrate: %v", err)
	}

	status, err := escrow.MigrationStatus(ctx, db.Pool())
	if err != nil {
		t.Fatalf("MigrationStatus: %v", err)
	}
	if len(status) == 0 {
		t.Fatal("MigrationStatus reported no migrations")
	}
	for _, s := range status {
		if !s.Applied {
			t.Fatalf("migration %d (%s) is not applied after Migrate", s.Version, s.Name)
		}
	}

	// Drop a policy by hand, then re-run: the reconciliation must put it back.
	// That is what "repairs" means, and it is the property a versioned
	// migration cannot have.
	if _, err := db.Pool().Exec(ctx, "DROP POLICY tenant_isolation ON escrow.seal"); err != nil {
		t.Fatalf("drop the policy this test exists to repair: %v", err)
	}
	if err := escrow.Migrate(ctx, db.Pool(), escrow.MigrateConfig{AppRole: appRole}); err != nil {
		t.Fatalf("Migrate after dropping a policy: %v", err)
	}

	var restrictive string
	if err := db.Pool().QueryRow(ctx,
		`SELECT permissive FROM pg_policies
		 WHERE schemaname = 'escrow' AND tablename = 'seal' AND policyname = 'tenant_isolation'`).
		Scan(&restrictive); err != nil {
		t.Fatalf("the dropped policy was not restored: %v", err)
	}
	if restrictive != "RESTRICTIVE" {
		t.Fatalf("the tenant policy is %s, want RESTRICTIVE: a permissive one is OR-ed away by any other permissive policy",
			restrictive)
	}

	// Every table this module owns carries the policy, and tenancy's own
	// sweep agrees there is no gap.
	uncovered, err := tenancy.AssertRLSCoverage(ctx, db.Pool(), migrate.Schema)
	if err != nil {
		t.Fatalf("AssertRLSCoverage: %v", err)
	}
	for _, table := range uncovered {
		if table != migrate.Schema+".goose_db_version" {
			t.Fatalf("%s carries no tenant policy", table)
		}
	}
}

func TestMigrateRequiresAnAppRole(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))
	err := escrow.Migrate(context.Background(), db.Pool(), escrow.MigrateConfig{})
	if !errors.Is(err, escrow.ErrInvalidConfig) {
		t.Fatalf("Migrate with no AppRole error = %v, want ErrInvalidConfig: "+
			"a default role name nobody chose is a deployment that looks secured and is not", err)
	}
}

func TestOpenValidatesItsConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tenant, err := escrow.ParseTenantID("t")
	if err != nil {
		t.Fatalf("ParseTenantID: %v", err)
	}

	for name, cfg := range map[string]escrow.Config{
		"no handle":          {Tenant: tenant},
		"no tenant":          {DB: (*pgxpool.Pool)(nil)},
		"a malformed role":   {DB: (*pgxpool.Pool)(nil), Tenant: tenant, AppRole: "role; DROP TABLE"},
		"a role with a dash": {DB: (*pgxpool.Pool)(nil), Tenant: tenant, AppRole: "escrow-app"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := escrow.Open(ctx, cfg); !errors.Is(err, escrow.ErrInvalidConfig) {
				t.Fatalf("Open error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// ---- harness ----

// migrator applies this module's schema, for testdb.WithMigrator. It opens and
// closes its own short-lived pool, which is what the two-pool model needs: the
// migration credential is not the credential run-time work uses.
func migrator(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open a migration pool: %w", err)
	}
	defer pool.Close()
	return escrow.Migrate(ctx, pool, escrow.MigrateConfig{AppRole: appRole})
}

// migratedPool returns a pool on a freshly created, freshly migrated database
// for this test. It skips under -short, through testdb.Start, which is the
// single chokepoint for that convention in this set of modules.
//
// The harness lives in tenancy rather than in a fourth copy of
// internal/testdb: CONVENTIONS.md settles that the shared container harness
// belongs there — tenant scoping and row-level security are what it exists to
// test, and this module's tests are exactly that — and cas's and audit's
// copies are a staged migration away from, not toward.
func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Start(t, testdb.WithMigrator(migrator)).Pool()
}

// freshTenant mints a tenant id unique within this test binary. Each one is a
// clean slate, because every row in this schema is tenant-scoped and
// row-level security is what keeps them apart.
func freshTenant(t *testing.T, n *atomic.Int64) escrow.TenantID {
	t.Helper()

	tenant, err := escrow.ParseTenantID("pgtest-" + strconv.FormatInt(n.Add(1), 10) + "-" + t.Name())
	if err != nil {
		// t.Name() can contain characters a tenant id may not, so fall back
		// to the counter alone rather than failing the test for a fixture.
		tenant, err = escrow.ParseTenantID("pgtest-" + strconv.FormatInt(n.Add(1), 10))
		if err != nil {
			t.Fatalf("ParseTenantID: %v", err)
		}
	}
	return tenant
}

// asAppRole runs fn inside a transaction narrowed to the application role,
// with the tenant context set to tenant (empty means "no tenant context").
//
// The role switch is the whole point: the pool connects as the container's
// superuser, and a superuser bypasses row security unconditionally, so an
// assertion made on the pool directly would prove nothing. SET LOCAL and
// set_config(..., true) are both transaction-scoped, so neither leaks across
// a reused pooled connection.
func asAppRole(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant string, fn func(tx pgx.Tx) error) error {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{appRole}.Sanitize()); err != nil {
		t.Fatalf("narrow into %s: %v", appRole, err)
	}
	if tenant != "" {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
			t.Fatalf("set the tenant context: %v", err)
		}
	}
	return fn(tx)
}

func createSeal(t *testing.T, tenant escrow.TenantID, required, total int) (escrow.Seal, escrow.SealedKey, []escrow.Share) {
	t.Helper()

	holders := make([]escrow.CustodianID, 0, total)
	for i := range total {
		id, err := escrow.ParseCustodianID("custodian-" + strconv.Itoa(i))
		if err != nil {
			t.Fatalf("ParseCustodianID: %v", err)
		}
		holders = append(holders, id)
	}
	seal, key, shares, err := escrow.Create(tenant, escrow.Plan{
		Threshold: escrow.Threshold{Required: required, Total: total},
		Holders:   holders,
		System:    holders[0],
		Liveness:  testSchedule(),
	}, escrow.SystemClock{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return seal, key, shares
}

func systemShare(t *testing.T, seal escrow.Seal, shares []escrow.Share) (mine escrow.Share, others []escrow.Share) {
	t.Helper()

	system, ok := seal.SystemCustodian()
	if !ok {
		t.Fatal("the fixture seal names no custodian inside the deployment")
	}
	for _, s := range shares {
		if s.Index() == system.Index {
			mine = s
			continue
		}
		others = append(others, s)
	}
	return mine, others
}

func destroyAll(key escrow.SealedKey, shares []escrow.Share) {
	key.Destroy()
	for i := range shares {
		shares[i].Destroy()
	}
}

// testSchedule is a liveness schedule that validates: three rungs over three
// independent channels, strictly advancing, with a grace period.
func testSchedule() escrow.LivenessSchedule {
	return escrow.LivenessSchedule{
		Since:   escrow.CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC)),
		CheckIn: 30 * 24 * time.Hour,
		Escalations: []escrow.Escalation{
			{After: 0, Channel: "email"},
			{After: 7 * 24 * time.Hour, Channel: "sms"},
			{After: 14 * 24 * time.Hour, Channel: "postal"},
		},
		Grace: 14 * 24 * time.Hour,
	}
}
