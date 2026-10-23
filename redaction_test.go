package escrow_test

import (
	"testing"

	"github.com/laenenai/escrow"
	"github.com/laenenai/escrow/escrowtest"
)

// TestSealedKeyAgainstTheSharedRenderingSubtest holds SealedKey to the shared NoSecretLeaksInAnyRendering helper, which
// is a byte-for-byte copy of the one every other module in this set carries.
//
// internal/domain has its own rendering test, and it covers more subjects —
// pointers, slices and maps of shares. This one covers more renderings, and the
// difference is the point: the domain test asserts %v, %s, %+v, %#v, %q, %x and
// json.Marshal, while fmt consults fmt.Stringer for only %v, %s, %q, %x and %X.
// The verbs that leaked an entire key in keyring were %d, %c, %U, %b and %o,
// which consult nothing but fmt.Formatter, and neither test covered slog's two
// handlers or asserted that all four interfaces are actually implemented.
//
// Both are kept. A module whose whole subject is material it must never release
// is the wrong place to economise on the test that proves it does not leak it.
//
// Share is not run through this helper, and cannot be: internal/domain cannot
// import escrowtest without a cycle, and the facade exposes no way to build a
// Share outside a sealing ceremony. Its own four methods are what cover the
// verbs the domain test misses, and TestSecretMaterialRendering asserts they
// are reached.
func TestSealedKeyAgainstTheSharedRenderingSubtest(t *testing.T) {
	t.Parallel()

	keyMaterial := make([]byte, escrow.KeySize)
	for i := range keyMaterial {
		keyMaterial[i] = byte(0xC0 + i)
	}
	key, err := escrow.SealedKeyFrom(keyMaterial)
	if err != nil {
		t.Fatalf("SealedKeyFrom() error = %v", err)
	}

	// The helper applies every rendering to a struct that merely contains the
	// subject as well as to the subject itself, so a containing type needs no
	// subtest of its own here.
	escrowtest.NoSecretLeaksInAnyRendering(t, key, keyMaterial)
}
