package pgstore

import (
	"testing"

	"github.com/laenenai/tenancy"

	"github.com/laenenai/escrow/internal/migrate"
)

// TestTenantGUCMatchesTenancy checks the one duplicated constant in this
// package against its source.
//
// tenantGUC is spelled out here rather than imported from tenancy, so that
// opening a store does not drag tenancy's pool and registry machinery in to
// set one session variable — internal/migrate is the package that imports
// tenancy, and only for EnableRLS. A duplicated constant is fine; a
// duplicated constant that has silently drifted is a store that sets a
// session variable no policy reads, which fails *open* in the worst possible
// way: every statement would see every tenant's rows and nothing would say so.
//
// So the duplication is checked rather than hoped for, and this test needs no
// database.
func TestTenantGUCMatchesTenancy(t *testing.T) {
	t.Parallel()

	if tenantGUC != tenancy.TenantGUC {
		t.Fatalf("pgstore's tenantGUC is %q but tenancy.TenantGUC is %q: "+
			"this store would set a session variable no policy reads, and every "+
			"statement would then see every tenant's rows", tenantGUC, tenancy.TenantGUC)
	}
	if !contains(tenancy.TenantPredicate, tenantGUC) {
		t.Fatalf("tenancy's predicate %q does not mention %q", tenancy.TenantPredicate, tenantGUC)
	}
}

// TestSchemaNameMatchesTheMigratedSchema checks the second piece of
// duplication: migrate.Schema creates the schema and this package's queries
// name it in SQL text that sqlc generated. sqlc checks those names against
// db/migrations at generation time, which is a stronger guarantee than this
// test — so what is left to check is that the Go constant an operator reads
// agrees with it.
func TestSchemaNameMatchesTheMigratedSchema(t *testing.T) {
	t.Parallel()

	if migrate.Schema != "escrow" {
		t.Fatalf("migrate.Schema = %q: the generated queries name escrow.* in SQL text", migrate.Schema)
	}
	for _, table := range migrate.Tables {
		if !contains(table, migrate.Schema+".") {
			t.Fatalf("table %q is not in schema %q", table, migrate.Schema)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
