package migrate

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/laenenai/tenancy"

	"github.com/laenenai/escrow/internal/domain"
)

// Tables is every table in this module's schema, qualified, in the order the
// reconciliation touches them.
//
// It is one list rather than a catalog sweep so that adding a table is a
// change to this slice — and therefore a change a reviewer sees next to the
// grants and the policies that must cover it. A sweep would silently include
// a new table before anybody had decided what its policy should be, and
// silently exclude one whose name did not match the pattern.
var Tables = []string{
	Schema + ".seal",
	Schema + ".custodian",
	Schema + ".escalation",
	Schema + ".held_share",
	Schema + ".proof_of_life",
	Schema + ".ceremony",
}

// enableTenantIsolation turns on row-level security for every table in this
// schema, through tenancy.EnableRLS.
//
// # Why this calls tenancy rather than writing policies by hand
//
// A live cross-tenant disclosure was found in this project on 2026-10-23, and
// this function exists in this shape because of it. Postgres **OR-s
// permissive policies together and AND-s restrictive ones over the result**,
// so a tenant predicate written as a single `AS PERMISSIVE` policy is OR-ed
// away by any later permissive policy on the same table. Measured on Postgres
// 18.6 against exactly that arrangement: a tenant seeing its own single row
// saw two the moment a second permissive policy existed, and the second row
// belonged to another tenant. Adding a policy weakened isolation — something
// any table owner can do, and that no consumer would expect.
//
// tenancy.EnableRLS installs the correct pair: the tenant predicate
// `AS RESTRICTIVE`, so it is AND-ed with everything and cannot be OR-ed away,
// plus a permissive companion `USING (true)` that grants nothing on its own
// and exists only so the restriction has something to AND against (a table
// whose only policies are restrictive has an empty permissive set, and
// Postgres then denies every row). A consumer may add as many permissive
// policies as it likes: they OR among themselves and the restriction still
// AND-s over the result, so a consumer can narrow within its tenant and
// cannot widen past it. escrowtest's
// RLSAnAddedPermissivePolicyCannotWidenAccess is that property as a test
// against a real database, and tenancytest carries the same assertion for the
// module that owns the mechanism.
//
// It also FORCEs row security, which matters because RLS does not apply to a
// table's owner by default: without FORCE the policies would appear in
// pg_policies while protecting nothing for any statement running as the
// owning role — a mode a deployment can sit in for a long time believing it
// is isolated. Neither FORCE nor anything else in SQL protects against a
// superuser connection, which bypasses row security unconditionally; that is
// what Config.AppRole and its NOBYPASSRLS are for.
//
// And it is idempotent and *repairing*: it drops each policy by name and
// recreates it inside one transaction, so re-running Up both tolerates the
// re-run and fixes a policy whose predicate has drifted. That is the whole
// reason this is reconciled on every Up rather than written into the
// versioned migration — a migration that has already been applied is never
// re-run, so a weakened policy would stay weakened forever while goose
// reported everything applied.
func enableTenantIsolation(ctx context.Context, tx pgx.Tx) error {
	if err := tenancy.EnableRLS(ctx, tx, Tables...); err != nil {
		return fmt.Errorf("%w: migrate: enable row-level security: %w", domain.ErrInvalidConfig, err)
	}
	return nil
}

// appRolePrivileges is what the application role is granted on every table in
// this schema.
//
// All four of SELECT, INSERT, UPDATE and DELETE, and that is a departure from
// audit worth stating rather than leaving to be noticed. audit revokes UPDATE
// and DELETE because an audit history that can be rewritten is not an audit
// history. **This module's tables are mutable by design:** a re-seal updates
// the seal row and replaces its custodian list (CHARTER.md's fourth safety
// property), and the deployment's single share is deleted when it is
// discarded. A schema that forbade those would forbid the charter.
//
// So this module makes no append-only claim about its own tables, and the
// tamper-evident record of what happened lives in `audit`, in audit's schema,
// under audit's privilege separation — see internal/trail. What
// row-level security protects here is tenant isolation, which is the claim
// this schema does make.
var appRolePrivileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}

// ensureAppRole creates the application role if it does not exist.
//
// NOLOGIN because nothing connects as it directly — a session reaches it with
// SET ROLE, which keeps the single-connection-string deployment model
// available. **NOBYPASSRLS** because a role that bypasses row security makes
// every policy in this schema decorative, and the default for CREATE ROLE is
// inherited from nothing in particular; saying it explicitly means a
// deployment cannot end up isolated-on-paper by accident.
//
// Roles are cluster-wide rather than per-database, so CREATE ROLE loses a
// race against a concurrent identical statement in a different database on
// the same cluster — which is exactly what happens when two consumers'
// migrations run at once. The duplicate is caught and treated as success;
// cas documented the same hazard.
func ensureAppRole(ctx context.Context, tx pgx.Tx, role string) error {
	// The role name cannot be a bound parameter in CREATE ROLE, so it reaches
	// Postgres as text — validated as a plain identifier by Config.resolve and
	// quoted here. The DO block is because CREATE ROLE has no IF NOT EXISTS.
	stmt := `
		DO $$
		BEGIN
		    BEGIN
		        CREATE ROLE ` + pgx.Identifier{role}.Sanitize() + ` NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
		    EXCEPTION
		        WHEN duplicate_object OR unique_violation THEN
		            NULL;
		    END;
		END
		$$`
	if _, err := tx.Exec(ctx, stmt); err != nil {
		if isDuplicateObject(err) {
			return nil
		}
		return fmt.Errorf("%w: migrate: ensure role %s: %w", domain.ErrInvalidConfig, role, err)
	}
	return nil
}

// grantToAppRole grants the application role usage of this schema and the
// privileges above on every table in it.
//
// Grants are on the tables named in Tables and on nothing else — no
// ALL TABLES IN SCHEMA, which would also grant whatever a future migration
// adds before anybody had decided it should be reachable, and no grants on
// escrow.goose_db_version, which is migration bookkeeping the application has
// no business reading or writing.
func grantToAppRole(ctx context.Context, tx pgx.Tx, role string) error {
	quoted := pgx.Identifier{role}.Sanitize()

	if _, err := tx.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{Schema}.Sanitize()+" TO "+quoted); err != nil {
		return fmt.Errorf("%w: migrate: grant usage on schema %s to %s: %w", domain.ErrInvalidConfig, Schema, role, err)
	}

	for _, table := range Tables {
		ident, err := qualified(table)
		if err != nil {
			return err
		}
		for _, privilege := range appRolePrivileges {
			if _, err := tx.Exec(ctx, "GRANT "+privilege+" ON "+ident+" TO "+quoted); err != nil {
				return fmt.Errorf("%w: migrate: grant %s on %s to %s: %w", domain.ErrInvalidConfig, privilege, table, role, err)
			}
		}
	}
	return nil
}

// qualified renders a "schema.table" string as two sanitized identifiers.
// Both halves come from Tables, a constant in this package, so this cannot
// fail in practice; it returns an error rather than assuming, because the one
// way it could fail is somebody adding an entry to Tables in the wrong shape
// and that should be a migration failure rather than malformed DDL.
func qualified(table string) (string, error) {
	schema, name, found := splitQualified(table)
	if !found {
		return "", fmt.Errorf("%w: migrate: table %q is not in schema.table form", domain.ErrInvalidConfig, table)
	}
	return pgx.Identifier{schema, name}.Sanitize(), nil
}

func splitQualified(table string) (schema, name string, found bool) {
	for i := range len(table) {
		if table[i] == '.' {
			return table[:i], table[i+1:], i > 0 && i < len(table)-1
		}
	}
	return "", "", false
}
