package sealstore_test

import (
	"errors"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/laenenai/escrow"
	"github.com/laenenai/escrow/escrowtest"
)

// TestMemoryStoreConformance runs the whole SealStore contract against the
// in-memory adapter. The suite is the authoritative description of that
// contract, so this is the test that says the adapter is correct — everything
// else in this file is about the adapter's own wiring.
//
// Each subtest gets its own store and its own tenant, which is also the shape
// the Postgres adapter uses: fresh state and tenant scoping from one
// mechanism.
func TestMemoryStoreConformance(t *testing.T) {
	t.Parallel()

	var n atomic.Int64
	escrowtest.RunSealStoreSuite(t, func(t *testing.T) escrowtest.Deployment {
		tenant, err := escrow.ParseTenantID("memtest-" + strconv.FormatInt(n.Add(1), 10))
		if err != nil {
			t.Fatalf("ParseTenantID: %v", err)
		}
		store, err := escrow.NewMemory(escrow.MemoryConfig{Tenant: tenant})
		if err != nil {
			t.Fatalf("NewMemory: %v", err)
		}
		return escrowtest.Deployment{Store: store, Tenant: tenant}
	})
}

// TestNewMemoryRequiresATenant: a constructor that accepted a zero tenant and
// then refused every seal would move the failure from the wiring to the first
// call.
func TestNewMemoryRequiresATenant(t *testing.T) {
	t.Parallel()

	store, err := escrow.NewMemory(escrow.MemoryConfig{})
	if !errors.Is(err, escrow.ErrInvalidConfig) {
		t.Fatalf("NewMemory with no tenant error = %v, want ErrInvalidConfig", err)
	}
	if store != nil {
		t.Fatal("NewMemory returned a store alongside an error")
	}
}
