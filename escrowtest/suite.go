// Package escrowtest is the conformance suite for the escrow module's
// SealStore port: RunSealStoreSuite is the authoritative description of the
// contract's edge-case behaviour, and an adapter counts as correct when it
// passes the suite unchanged.
//
// It is a sibling package rather than a suite.go inside the port's own
// package, and rather than a _test.go file, because both alternatives fail a
// requirement:
//
//   - Identifiers declared in a _test.go file are not importable from outside
//     that package, and this suite must be callable from another module
//     entirely. CHARTER.md counts a consumer as having adopted this module
//     when this suite runs green in that consumer's CI against its own
//     wiring — which is what makes "adopted" testable rather than asserted.
//   - A non-test file that imports testing makes testing a dependency of the
//     production package, so every consumer's binary links it and inherits
//     its flag registrations. Keeping the suite here keeps testing out of the
//     production import graph.
//
// This is the standard library's own shape: net/http/httptest is a sibling of
// net/http, and testing/fstest.TestFS verifies any fs.FS.
//
// # What the suite proves, and what it cannot
//
// It proves the *contract*. Four of its subtests are named after CHARTER.md's
// safety properties and exist so that no adapter can quietly skip one:
//
//   - SystemHoldsAtMostOneShare and SystemSharesAreNeverSufficient —
//     property 1.
//   - ReSealRotatesTheKeyAndDiscardsTheHeldShare — property 4.
//   - NoSecretLeaksInAnyRendering — the rendering discipline every type
//     holding share material is held to.
//
// What it cannot prove is *enforcement* belonging to something outside the
// process: that a database refuses a second share by its primary key rather
// than by a read-then-insert in Go, that row-level security fails closed, or
// that an added permissive policy cannot widen access. An in-memory adapter
// passes this suite and offers none of those. Those live in the Postgres
// adapter's own tests, against a real database, which is why a module whose
// only adapter is in-memory is an unfinished module.
package escrowtest

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laenenai/escrow"
	"github.com/laenenai/escrow/internal/domain"
)

// Deployment is what a factory hands the suite: a store and the tenant it is
// scoped to.
//
// The tenant is in here rather than fixed by the suite because a store is
// opened scoped to one tenant and refuses a seal belonging to another, so the
// suite has to build its fixtures for the tenant the adapter was actually
// opened for. It is also what lets a Postgres adapter give each subtest a
// fresh tenant instead of a fresh database, which is both faster and a
// stronger test — fresh state *and* tenant scoping, from one mechanism.
type Deployment struct {
	// Store is the adapter under test, empty of seals for this tenant.
	Store escrow.SealStore
	// Tenant is the tenant Store is scoped to.
	Tenant escrow.TenantID
}

// RunSealStoreSuite runs the contract every escrow.SealStore adapter must
// satisfy.
//
// newDeployment is called once per subtest, receiving that subtest's own *T,
// so an adapter that needs per-test setup and teardown (a fresh tenant, a
// scratch schema, a container it starts) registers it with t.Cleanup inside
// newDeployment and gets fresh, isolated state for every subtest. Each
// subtest assumes it is handed a store holding no seals for its tenant.
//
// Every assertion here must hold for any store — maps behind a mutex, a
// Postgres schema, something else. Nothing here inspects storage directly or
// assumes a particular backend; adapter-specific mechanics (which constraint
// refuses a second share, what happens when the database is unreachable, how
// row-level security behaves) belong in that adapter's own test file.
func RunSealStoreSuite(t *testing.T, newDeployment func(t *testing.T) Deployment) {
	t.Helper()

	t.Run("EmptyStoreHasNoSeal", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		id := mustSealID(t)
		if _, err := dep.Store.Seal(ctx, id); !errors.Is(err, escrow.ErrSealNotFound) {
			t.Fatalf("Seal on an empty store error = %v, want ErrSealNotFound", err)
		}
		if _, err := dep.Store.HeldShare(ctx, id); err == nil {
			t.Fatal("HeldShare on an empty store returned a share")
		}
		if _, err := dep.Store.ProofsOfLife(ctx, id); !errors.Is(err, escrow.ErrSealNotFound) {
			t.Fatalf("ProofsOfLife for an unknown seal error = %v, want ErrSealNotFound", err)
		}
		if _, err := dep.Store.Ceremonies(ctx, id); !errors.Is(err, escrow.ErrSealNotFound) {
			t.Fatalf("Ceremonies for an unknown seal error = %v, want ErrSealNotFound", err)
		}
	})

	// A seal is the record a ceremony is run against, and it must come back
	// exactly as it went in — a threshold, a commitment or a schedule that
	// round-tripped approximately is a ceremony that behaves differently from
	// the one that was agreed.
	t.Run("CreateSealRoundTripsEveryField", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 3, 5)
		defer destroyAll(key, shares)

		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		got, err := dep.Store.Seal(ctx, seal.ID)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		assertSealsEqual(t, seal, got)

		// The commitment in particular: it is the only value in the record
		// that cannot be reconstructed from anything else, and a seal whose
		// commitment did not survive storage is a seal nothing can be
		// verified against.
		if !got.Commitment.Equal(seal.Commitment) {
			t.Fatal("the key commitment did not round-trip")
		}
		reconstructed, err := escrow.Reconstruct(got, shares[:3])
		if err != nil {
			t.Fatalf("Reconstruct against the stored seal: %v", err)
		}
		if !reconstructed.Equal(key) {
			t.Fatal("the stored seal verified a different key")
		}
		reconstructed.Destroy()
	})

	t.Run("CreateSealRefusesADuplicate", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)

		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		if err := dep.Store.CreateSeal(ctx, seal); !errors.Is(err, escrow.ErrSealExists) {
			t.Fatalf("second CreateSeal error = %v, want ErrSealExists", err)
		}

		// And it must not have overwritten anything: the commitment the first
		// create stored is what the distributed shares were cut against.
		got, err := dep.Store.Seal(ctx, seal.ID)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if !got.Commitment.Equal(seal.Commitment) {
			t.Fatal("a refused CreateSeal changed the stored commitment")
		}
	})

	t.Run("CreateSealRefusesWhatCannotBeACustodyArrangement", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)

		cases := map[string]func(s *escrow.Seal){
			// CHARTER property 1: a threshold of one would let the deployment
			// open the seal with the single share it holds.
			"a 1-of-3 threshold": func(s *escrow.Seal) {
				s.Threshold = escrow.Threshold{Required: 1, Total: 3}
			},
			"two shares inside the deployment": func(s *escrow.Seal) {
				s.Custodians[0].Holder = escrow.HolderSystem
				s.Custodians[1].Holder = escrow.HolderSystem
			},
			"no key commitment": func(s *escrow.Seal) { s.Commitment = escrow.KeyCommitment{} },
			"a duplicate custodian": func(s *escrow.Seal) {
				s.Custodians[1].ID = s.Custodians[0].ID
			},
			"a duplicate share index": func(s *escrow.Seal) {
				s.Custodians[1].Index = s.Custodians[0].Index
			},
			"fewer custodians than shares": func(s *escrow.Seal) {
				s.Custodians = s.Custodians[:2]
			},
			// CHARTER property 3: a schedule with no grace period is a switch
			// that fires on the same instant as its final warning.
			"no grace period": func(s *escrow.Seal) { s.Liveness.Grace = 0 },
			"one notification channel": func(s *escrow.Seal) {
				s.Liveness.Escalations = []escrow.Escalation{
					{After: 0, Channel: "email"},
					{After: time.Hour, Channel: "email"},
				}
			},
			"a non-canonical instant": func(s *escrow.Seal) {
				s.SealedAt = s.SealedAt.Add(time.Nanosecond)
			},
			"another tenant's seal": func(s *escrow.Seal) {
				s.Tenant = mustTenant(t, "some-other-tenant")
			},
			"a later generation": func(s *escrow.Seal) { s.Generation = s.Generation.Next() },
		}

		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				bad := seal.Clone()
				mutate(&bad)
				if err := dep.Store.CreateSeal(ctx, bad); err == nil {
					t.Fatal("the store accepted it")
				}
				if _, err := dep.Store.Seal(ctx, bad.ID); !errors.Is(err, escrow.ErrSealNotFound) {
					t.Fatalf("a refused CreateSeal stored something: Seal error = %v", err)
				}
			})
		}
	})

	// SystemHoldsAtMostOneShare is CHARTER.md's first safety property as the
	// store enforces it. The second share is refused rather than overwriting
	// the first, because overwriting would silently destroy a share a
	// custodian may already have been told the deployment holds.
	t.Run("SystemHoldsAtMostOneShare", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 3, 5)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}

		mine, others := splitShares(t, seal, shares)
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}

		// The same share again.
		if err := dep.Store.HoldShare(ctx, mine); !errors.Is(err, escrow.ErrShareAlreadyHeld) {
			t.Fatalf("holding the same share twice error = %v, want ErrShareAlreadyHeld", err)
		}
		// A different share of the same seal — the dangerous one, because it
		// would be a second share rather than a duplicate.
		if err := dep.Store.HoldShare(ctx, others[0]); err == nil {
			t.Fatal("the store accepted a second share for one seal: CHARTER.md's first safety property is that it holds at most one")
		}

		// And exactly one is held, still the first.
		held, err := dep.Store.HeldShare(ctx, seal.ID)
		if err != nil {
			t.Fatalf("HeldShare: %v", err)
		}
		if held.Index() != mine.Index() {
			t.Fatalf("the held share is at index %d, want the first one held (%d)", held.Index(), mine.Index())
		}
	})

	// SystemSharesAreNeverSufficient is the other half of property 1: not
	// merely that the deployment holds one share, but that one share is below
	// the threshold for every seal the API accepts — so the deployment cannot
	// unseal on its own.
	//
	// The exhaustive enumeration over all (M, N) lives in internal/threshold's
	// tests, where it is cheap. Here it is asserted operationally, including
	// for the smallest and most dangerous arrangement, a 2-of-2 seal.
	t.Run("SystemSharesAreNeverSufficient", func(t *testing.T) {
		for _, th := range []escrow.Threshold{{Required: 2, Total: 2}, {Required: 2, Total: 3}, {Required: 3, Total: 5}, {Required: 5, Total: 9}} {
			t.Run(th.String(), func(t *testing.T) {
				dep := newDeployment(t)
				ctx := context.Background()

				seal, key, shares := mustCreate(t, dep, th.Required, th.Total)
				defer destroyAll(key, shares)
				if err := dep.Store.CreateSeal(ctx, seal); err != nil {
					t.Fatalf("CreateSeal: %v", err)
				}

				mine, _ := splitShares(t, seal, shares)
				if err := dep.Store.HoldShare(ctx, mine); err != nil {
					t.Fatalf("HoldShare: %v", err)
				}

				stored, err := dep.Store.Seal(ctx, seal.ID)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				if stored.SystemHeldShares() > escrow.MaxSystemHeldShares {
					t.Fatalf("the stored seal puts %d shares inside the deployment, at most %d may be",
						stored.SystemHeldShares(), escrow.MaxSystemHeldShares)
				}
				if stored.IsSystemSufficient() {
					t.Fatal("the stored seal reports the deployment as able to reach its own threshold")
				}

				// Operationally: everything the deployment holds, presented on
				// its own, must not open the seal.
				held, err := dep.Store.HeldShare(ctx, seal.ID)
				if err != nil {
					t.Fatalf("HeldShare: %v", err)
				}
				got, err := escrow.Reconstruct(stored, []escrow.Share{held})
				if err == nil {
					got.Destroy()
					t.Fatal("the deployment reconstructed the key from its own single share")
				}
				if !errors.Is(err, escrow.ErrInsufficientShares) {
					t.Fatalf("Reconstruct from the held share alone error = %v, want ErrInsufficientShares", err)
				}
			})
		}

		t.Run("a 1-of-N seal cannot be created at all", func(t *testing.T) {
			dep := newDeployment(t)
			_, _, _, err := escrow.Create(dep.Tenant, escrow.Plan{
				Threshold: escrow.Threshold{Required: 1, Total: 3},
				Holders:   []escrow.CustodianID{mustCustodian(t, "a"), mustCustodian(t, "b"), mustCustodian(t, "c")},
				System:    mustCustodian(t, "a"),
				Liveness:  testSchedule(),
			}, escrow.NewFixedClock(testNow()))
			if !errors.Is(err, escrow.ErrInvalidThreshold) {
				t.Fatalf("Create with a 1-of-3 threshold error = %v, want ErrInvalidThreshold: "+
					"the deployment holds one share, so a 1-of-N seal is one it could open alone", err)
			}
		})
	})

	t.Run("HoldShareRefusesAShareThatIsNotTheDeploymentsOwn", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 3, 5)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, others := splitShares(t, seal, shares)

		t.Run("an external custodian's index", func(t *testing.T) {
			// A share assigned to a lawyer turning up in the deployment's own
			// storage is the distribution of shares silently changing, and the
			// distribution is what keeps the deployment insufficient.
			if err := dep.Store.HoldShare(ctx, others[0]); !errors.Is(err, escrow.ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})

		t.Run("a share of a generation the seal is not at", func(t *testing.T) {
			ahead := rebind(t, mine, seal.ID, seal.Generation.Next())
			if err := dep.Store.HoldShare(ctx, ahead); !errors.Is(err, escrow.ErrForeignShare) {
				t.Fatalf("error = %v, want ErrForeignShare", err)
			}
		})

		t.Run("a share of a seal that is not stored", func(t *testing.T) {
			elsewhere := rebind(t, mine, mustSealID(t), escrow.FirstGeneration)
			if err := dep.Store.HoldShare(ctx, elsewhere); !errors.Is(err, escrow.ErrSealNotFound) {
				t.Fatalf("error = %v, want ErrSealNotFound", err)
			}
		})

		t.Run("after all of which nothing is held", func(t *testing.T) {
			if _, err := dep.Store.HeldShare(ctx, seal.ID); !errors.Is(err, escrow.ErrNoHeldShare) {
				t.Fatalf("HeldShare error = %v, want ErrNoHeldShare: a refused HoldShare stored something", err)
			}
		})
	})

	t.Run("HeldShareRoundTripsAndIsACopy", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, others := splitShares(t, seal, shares)
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}

		held, err := dep.Store.HeldShare(ctx, seal.ID)
		if err != nil {
			t.Fatalf("HeldShare: %v", err)
		}
		if held.Seal() != mine.Seal() || held.Generation() != mine.Generation() || held.Index() != mine.Index() {
			t.Fatalf("the binding did not round-trip: got %v, want %v", held, mine)
		}

		// It must actually be the share: combined with a quorum's worth of
		// others it reconstructs the key.
		got, err := escrow.Reconstruct(seal, []escrow.Share{held, others[0]})
		if err != nil {
			t.Fatalf("Reconstruct with the held share: %v", err)
		}
		if !got.Equal(key) {
			t.Fatal("the held share reconstructed a different key")
		}
		got.Destroy()

		// A caller that destroys what it was given must not destroy the share
		// the deployment still holds.
		held.Destroy()
		again, err := dep.Store.HeldShare(ctx, seal.ID)
		if err != nil {
			t.Fatalf("HeldShare after the caller destroyed its copy: %v", err)
		}
		if again.IsZero() {
			t.Fatal("destroying the returned share zeroized the stored one")
		}
	})

	t.Run("DiscardHeldShareLeavesTheSealIntact", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, _ := splitShares(t, seal, shares)

		if err := dep.Store.DiscardHeldShare(ctx, seal.ID); !errors.Is(err, escrow.ErrNoHeldShare) {
			t.Fatalf("discarding nothing error = %v, want ErrNoHeldShare", err)
		}
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}
		if err := dep.Store.DiscardHeldShare(ctx, seal.ID); err != nil {
			t.Fatalf("DiscardHeldShare: %v", err)
		}
		if _, err := dep.Store.HeldShare(ctx, seal.ID); !errors.Is(err, escrow.ErrNoHeldShare) {
			t.Fatalf("HeldShare after a discard error = %v, want ErrNoHeldShare", err)
		}
		// The seal survives: a deployment handing its share to a human and
		// keeping none strengthens the seal rather than destroying it.
		if _, err := dep.Store.Seal(ctx, seal.ID); err != nil {
			t.Fatalf("Seal after discarding its share: %v", err)
		}
		// And the share can be held again, which is what makes the discard a
		// discard rather than a one-way door.
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare after a discard: %v", err)
		}
	})

	// ReSealRotatesTheKeyAndDiscardsTheHeldShare is CHARTER.md's fourth
	// safety property as the store enforces it. The assertion is that old
	// shares **fail**, not that they are marked stale — and that the
	// deployment's own superseded share is gone rather than left to look
	// current.
	t.Run("ReSealRotatesTheKeyAndDiscardsTheHeldShare", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, oldKey, oldShares := mustCreate(t, dep, 2, 3)
		defer destroyAll(oldKey, oldShares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, _ := splitShares(t, seal, oldShares)
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}

		rotated, newKey, newShares, err := escrow.Rotate(seal, escrow.PlanFrom(seal),
			escrow.NewFixedClock(testNow().Add(time.Hour)))
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		defer destroyAll(newKey, newShares)

		if err := dep.Store.ReplaceSeal(ctx, rotated); err != nil {
			t.Fatalf("ReplaceSeal: %v", err)
		}

		stored, err := dep.Store.Seal(ctx, seal.ID)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if stored.Generation != seal.Generation.Next() {
			t.Fatalf("the stored seal is at %s, want %s", stored.Generation, seal.Generation.Next())
		}
		if stored.Commitment.Equal(seal.Commitment) {
			t.Fatal("the stored commitment did not change: a re-seal that keeps the key leaves every distributed share able to open it")
		}
		if !stored.CreatedAt.Equal(seal.CreatedAt) {
			t.Fatal("a re-seal changed the seal's creation instant")
		}

		// The deployment's superseded share went with the generation, in the
		// same operation — a caller that rotated and then failed before
		// discarding would be holding a share that is useless and looks
		// current.
		if _, err := dep.Store.HeldShare(ctx, seal.ID); !errors.Is(err, escrow.ErrNoHeldShare) {
			t.Fatalf("HeldShare after a re-seal error = %v, want ErrNoHeldShare: the superseded share was not discarded", err)
		}

		// The old shares fail against the new seal, as themselves and with
		// their binding rewritten.
		if got, err := escrow.Reconstruct(stored, oldShares[:2]); !errors.Is(err, escrow.ErrForeignShare) {
			got.Destroy()
			t.Fatalf("old shares against the rotated seal error = %v, want ErrForeignShare", err)
		}
		forged := []escrow.Share{
			rebind(t, oldShares[0], stored.ID, stored.Generation),
			rebind(t, oldShares[1], stored.ID, stored.Generation),
		}
		if got, err := escrow.Reconstruct(stored, forged); !errors.Is(err, escrow.ErrReconstructionUnverified) {
			got.Destroy()
			t.Fatalf("old shares rebound to the new generation error = %v, want ErrReconstructionUnverified: "+
				"a re-seal that only labels old shares stale is not CHARTER.md's property 4", err)
		}

		// The new shares open the new seal, so the rotation is a rotation and
		// not a bricking.
		got, err := escrow.Reconstruct(stored, newShares[:2])
		if err != nil {
			t.Fatalf("Reconstruct with the new shares: %v", err)
		}
		if !got.Equal(newKey) {
			t.Fatal("the new shares reconstructed a different key")
		}
		got.Destroy()

		// And the deployment can hold its new share.
		newMine, _ := splitShares(t, stored, newShares)
		if err := dep.Store.HoldShare(ctx, newMine); err != nil {
			t.Fatalf("HoldShare after a re-seal: %v", err)
		}
	})

	t.Run("ReplaceSealRefusesAGenerationThatDoesNotFollow", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)

		// Not stored yet.
		rotated, newKey, newShares, err := escrow.Rotate(seal, escrow.PlanFrom(seal), escrow.NewFixedClock(testNow().Add(time.Hour)))
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		defer destroyAll(newKey, newShares)
		if err := dep.Store.ReplaceSeal(ctx, rotated); !errors.Is(err, escrow.ErrSealNotFound) {
			t.Fatalf("ReplaceSeal on an unstored seal error = %v, want ErrSealNotFound", err)
		}

		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}

		t.Run("the same generation", func(t *testing.T) {
			same := seal.Clone()
			same.SealedAt = same.SealedAt.Add(time.Hour)
			if err := dep.Store.ReplaceSeal(ctx, same); !errors.Is(err, escrow.ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})

		t.Run("a skipped generation", func(t *testing.T) {
			// A gap would make a share from the skipped generation
			// indistinguishable from a share of a generation that never
			// existed, which is the whole value of the field.
			skipped := rotated.Clone()
			skipped.Generation = skipped.Generation.Next()
			if err := dep.Store.ReplaceSeal(ctx, skipped); !errors.Is(err, escrow.ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})

		t.Run("a changed creation instant", func(t *testing.T) {
			moved := rotated.Clone()
			moved.CreatedAt = moved.CreatedAt.Add(-time.Hour)
			if err := dep.Store.ReplaceSeal(ctx, moved); !errors.Is(err, escrow.ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})

		t.Run("after all of which the seal is untouched", func(t *testing.T) {
			got, err := dep.Store.Seal(ctx, seal.ID)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if got.Generation != seal.Generation || !got.Commitment.Equal(seal.Commitment) {
				t.Fatal("a refused ReplaceSeal changed the stored seal")
			}
		})
	})

	t.Run("ProofsOfLifeAreRecordedAndOrdered", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}

		// Recorded out of order on purpose: a store returns them in
		// chronological order whatever order they arrived in, because that is
		// what the liveness evaluation and every human investigation want.
		offsets := []time.Duration{3 * time.Hour, time.Hour, 5 * time.Hour, 2 * time.Hour}
		channels := []escrow.ChannelID{"email", "sms", "email", "postal"}
		for i, offset := range offsets {
			proof := mustProof(t, seal.ID, testNow().Add(offset), channels[i])
			if err := dep.Store.RecordProofOfLife(ctx, proof); err != nil {
				t.Fatalf("RecordProofOfLife: %v", err)
			}
		}

		got, err := dep.Store.ProofsOfLife(ctx, seal.ID)
		if err != nil {
			t.Fatalf("ProofsOfLife: %v", err)
		}
		if len(got) != len(offsets) {
			t.Fatalf("recorded %d proofs, read back %d", len(offsets), len(got))
		}
		for i := 1; i < len(got); i++ {
			if got[i].At.Before(got[i-1].At) {
				t.Fatalf("proofs are not in chronological order: %s then %s", got[i-1].At, got[i].At)
			}
		}
		if !got[0].At.Equal(escrow.CanonicalTime(testNow().Add(time.Hour))) {
			t.Fatalf("the first proof is at %s, want the earliest recorded", got[0].At)
		}
		for _, p := range got {
			if p.Seal != seal.ID {
				t.Fatalf("a proof came back bound to seal %s", p.Seal)
			}
			if p.Channel == "" {
				t.Fatal("a proof came back with no channel: its provenance is the one thing an investigation cannot reconstruct")
			}
		}

		// Every proof the liveness machine needs is here, and it evaluates
		// against the stored schedule.
		stored, err := dep.Store.Seal(ctx, seal.ID)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		liveness, err := escrow.EvaluateLiveness(stored.Liveness, got, testNow().Add(6*time.Hour))
		if err != nil {
			t.Fatalf("EvaluateLiveness over the stored proofs: %v", err)
		}
		if liveness.State != escrow.StateAlive {
			t.Fatalf("a seal with a proof of life an hour ago is %s, want %s", liveness.State, escrow.StateAlive)
		}
	})

	t.Run("ProofOfLifeRedeliveryIsOneRecordAndAConflictIsRefused", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}

		proof := mustProof(t, seal.ID, testNow().Add(time.Hour), "email")
		for range 3 {
			// The channels a proof arrives on retry; three deliveries of one
			// proof must be one proof and not an error.
			if err := dep.Store.RecordProofOfLife(ctx, proof); err != nil {
				t.Fatalf("RecordProofOfLife on redelivery: %v", err)
			}
		}
		got, err := dep.Store.ProofsOfLife(ctx, seal.ID)
		if err != nil {
			t.Fatalf("ProofsOfLife: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("three deliveries of one proof produced %d records", len(got))
		}

		// The same id carrying something different is not a retry.
		conflicting := proof
		conflicting.At = proof.At.Add(time.Hour)
		if err := dep.Store.RecordProofOfLife(ctx, conflicting); !errors.Is(err, escrow.ErrInvalidArgument) {
			t.Fatalf("a different proof reusing an id error = %v, want ErrInvalidArgument", err)
		}

		// And a proof for a seal that is not stored.
		elsewhere := mustProof(t, mustSealID(t), testNow(), "email")
		if err := dep.Store.RecordProofOfLife(ctx, elsewhere); !errors.Is(err, escrow.ErrSealNotFound) {
			t.Fatalf("a proof for an unknown seal error = %v, want ErrSealNotFound", err)
		}
	})

	// CHARTER.md: the trail must hold "every proof-of-life, notification,
	// share release and unseal attempt — including the failed ones, which are
	// the interesting signal." A store that only recorded successful
	// ceremonies would make the question anybody actually asks of this record
	// — who tried — unanswerable.
	t.Run("CeremoniesRecordRefusalsAndFailuresAsWellAsCompletions", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}

		want := []escrow.Ceremony{
			testCeremony(t, dep, seal, escrow.ReleaseByLivenessLapse, escrow.CeremonyCompleted, testNow().Add(time.Hour), ""),
			testCeremony(t, dep, seal, escrow.ReleaseByThreshold, escrow.CeremonyRefused, testNow().Add(2*time.Hour),
				"two shares presented, the set failed its commitment"),
			testCeremony(t, dep, seal, escrow.ReleaseByHumanAct, escrow.CeremonyFailed, testNow().Add(3*time.Hour),
				"the store was unreachable"),
		}
		for _, c := range want {
			if err := dep.Store.RecordCeremony(ctx, c); err != nil {
				t.Fatalf("RecordCeremony(%s/%s): %v", c.Condition, c.Outcome, err)
			}
		}

		got, err := dep.Store.Ceremonies(ctx, seal.ID)
		if err != nil {
			t.Fatalf("Ceremonies: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("recorded %d ceremonies, read back %d: the refusals and failures must be kept", len(want), len(got))
		}
		for i := range want {
			if !got[i].Equal(want[i]) {
				t.Fatalf("ceremony %d did not round-trip:\n got %+v\nwant %+v", i, got[i], want[i])
			}
		}
		for i := 1; i < len(got); i++ {
			if got[i].At.Before(got[i-1].At) {
				t.Fatal("ceremonies are not in chronological order")
			}
		}

		// Redelivery is one record; a conflict is refused.
		if err := dep.Store.RecordCeremony(ctx, want[1]); err != nil {
			t.Fatalf("RecordCeremony on redelivery: %v", err)
		}
		conflicting := want[1].Clone()
		conflicting.Reason = "something else entirely"
		if err := dep.Store.RecordCeremony(ctx, conflicting); !errors.Is(err, escrow.ErrInvalidArgument) {
			t.Fatalf("a different ceremony reusing an id error = %v, want ErrInvalidArgument", err)
		}

		// A ceremony ahead of the seal's generation is a bug: the arrangement
		// it claims to have been run against does not exist yet.
		ahead := testCeremony(t, dep, seal, escrow.ReleaseByHumanAct, escrow.CeremonyCompleted, testNow().Add(4*time.Hour), "")
		ahead.Generation = seal.Generation.Next()
		if err := dep.Store.RecordCeremony(ctx, ahead); !errors.Is(err, escrow.ErrInvalidArgument) {
			t.Fatalf("a ceremony ahead of the seal error = %v, want ErrInvalidArgument", err)
		}

		// A ceremony claiming a liveness lapse unsealed something must be
		// unstorable: CHARTER.md's second safety property.
		lying := testCeremony(t, dep, seal, escrow.ReleaseByLivenessLapse, escrow.CeremonyCompleted, testNow().Add(5*time.Hour), "")
		lying.Effect = escrow.EffectUnseal
		if err := dep.Store.RecordCeremony(ctx, lying); err == nil {
			t.Fatal("the store accepted a ceremony recording that a liveness lapse unsealed the content")
		}
	})

	// NoSecretLeaksInAnyRendering holds a share that came **out of the
	// store** to the module's rendering discipline: all four of Stringer,
	// Formatter, json.Marshaler and LogValuer, none of the five renderings
	// containing the material, any encoding of it, or its length in decimal.
	//
	// Asserted here, in the suite, because an adapter that returned its own
	// share-shaped type, or that put material into a struct it logged, would
	// defeat the discipline while passing every other subtest.
	t.Run("NoSecretLeaksInAnyRendering", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, _ := splitShares(t, seal, shares)
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}

		held, err := dep.Store.HeldShare(ctx, seal.ID)
		if err != nil {
			t.Fatalf("HeldShare: %v", err)
		}
		material := append([]byte(nil), held.Material()...)
		keyBytes := append([]byte(nil), key.Bytes()...)

		type carrier struct {
			Note  string
			Key   escrow.SealedKey
			Share escrow.Share
			Seal  escrow.Seal
		}
		subjects := map[string]any{
			"the held share":                held,
			"a pointer to it":               &held,
			"the key":                       key,
			"a struct containing both":      carrier{Note: "logged by accident", Key: key, Share: held, Seal: seal},
			"a slice of shares":             shares,
			"the seal, which holds neither": seal,
		}

		for name, subject := range subjects {
			t.Run(name, func(t *testing.T) {
				renderings := map[string]string{
					"%v":  fmt.Sprintf("%v", subject),
					"%s":  fmt.Sprintf("%s", subject),
					"%+v": fmt.Sprintf("%+v", subject),
					"%#v": fmt.Sprintf("%#v", subject),
				}
				encoded, err := json.Marshal(subject)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				renderings["json.Marshal"] = string(encoded)

				for verb, text := range renderings {
					assertNoSecret(t, verb, text, publicIdentifiers(seal), keyBytes, material)
				}
			})
		}
	})

	// NoShareMaterialLeaksInErrors is the other half of the rendering
	// discipline: the release and unseal paths hold both a key and share
	// bytes, and an error string is the value most likely to reach a log file
	// somebody else can read.
	t.Run("NoShareMaterialLeaksInErrors", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, others := splitShares(t, seal, shares)
		if err := dep.Store.HoldShare(ctx, mine); err != nil {
			t.Fatalf("HoldShare: %v", err)
		}

		secrets := [][]byte{append([]byte(nil), key.Bytes()...)}
		for _, s := range shares {
			secrets = append(secrets, append([]byte(nil), s.Material()...))
		}

		errorPaths := map[string]func() error{
			"a second share": func() error { return dep.Store.HoldShare(ctx, mine) },
			"another custodian's share": func() error {
				return dep.Store.HoldShare(ctx, others[0])
			},
			"a share of an unknown seal": func() error {
				return dep.Store.HoldShare(ctx, rebind(t, mine, mustSealID(t), escrow.FirstGeneration))
			},
			"a share of the wrong generation": func() error {
				return dep.Store.HoldShare(ctx, rebind(t, mine, seal.ID, seal.Generation.Next()))
			},
			"reading an unknown seal's share": func() error {
				_, err := dep.Store.HeldShare(ctx, mustSealID(t))
				return err
			},
			"a refused reconstruction": func() error {
				_, err := escrow.Reconstruct(seal, []escrow.Share{mine})
				return err
			},
		}

		for name, run := range errorPaths {
			t.Run(name, func(t *testing.T) {
				err := run()
				if err == nil {
					t.Fatal("expected a refusal")
				}
				assertNoSecret(t, "the error", err.Error(), publicIdentifiers(seal), secrets...)
			})
		}
	})

	// A cancelled context must be honoured rather than ignored. An adapter
	// that silently completed a share release for a request that had already
	// gone away would be releasing a share nobody asked for.
	t.Run("CanceledContextIsRefused", func(t *testing.T) {
		dep := newDeployment(t)

		seal, key, shares := mustCreate(t, dep, 2, 3)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(context.Background(), seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, _ := splitShares(t, seal, shares)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		calls := map[string]func() error{
			"CreateSeal":        func() error { return dep.Store.CreateSeal(ctx, seal) },
			"Seal":              func() error { _, err := dep.Store.Seal(ctx, seal.ID); return err },
			"ReplaceSeal":       func() error { return dep.Store.ReplaceSeal(ctx, seal) },
			"HoldShare":         func() error { return dep.Store.HoldShare(ctx, mine) },
			"HeldShare":         func() error { _, err := dep.Store.HeldShare(ctx, seal.ID); return err },
			"DiscardHeldShare":  func() error { return dep.Store.DiscardHeldShare(ctx, seal.ID) },
			"RecordProofOfLife": func() error { return dep.Store.RecordProofOfLife(ctx, mustProof(t, seal.ID, testNow(), "email")) },
			"ProofsOfLife":      func() error { _, err := dep.Store.ProofsOfLife(ctx, seal.ID); return err },
			"RecordCeremony": func() error {
				return dep.Store.RecordCeremony(ctx, testCeremony(t, dep, seal, escrow.ReleaseByHumanAct, escrow.CeremonyCompleted, testNow(), ""))
			},
			"Ceremonies": func() error { _, err := dep.Store.Ceremonies(ctx, seal.ID); return err },
		}
		for name, call := range calls {
			t.Run(name, func(t *testing.T) {
				if err := call(); !errors.Is(err, context.Canceled) {
					t.Fatalf("%s with a cancelled context error = %v, want context.Canceled", name, err)
				}
			})
		}

		// And the adapter must still work afterwards.
		if _, err := dep.Store.Seal(context.Background(), seal.ID); err != nil {
			t.Fatalf("a cancelled context must not have broken the adapter: %v", err)
		}
	})

	// ConcurrentHoldShareYieldsOneWinner is CHARTER.md's first safety property
	// under concurrency, which is where a read-then-insert in Go stops being
	// enough: exactly one of N simultaneous attempts may succeed, and the
	// others must be refused rather than overwrite.
	t.Run("ConcurrentHoldShareYieldsOneWinner", func(t *testing.T) {
		dep := newDeployment(t)
		ctx := context.Background()

		seal, key, shares := mustCreate(t, dep, 3, 5)
		defer destroyAll(key, shares)
		if err := dep.Store.CreateSeal(ctx, seal); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
		mine, _ := splitShares(t, seal, shares)

		const attempts = 8
		var wg sync.WaitGroup
		errs := make([]error, attempts)
		start := make(chan struct{})
		for i := range attempts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = dep.Store.HoldShare(ctx, mine)
			}()
		}
		close(start)
		wg.Wait()

		winners := 0
		for i, err := range errs {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, escrow.ErrShareAlreadyHeld):
			default:
				t.Fatalf("attempt %d failed with an unexpected error: %v", i, err)
			}
		}
		if winners != 1 {
			t.Fatalf("%d of %d concurrent HoldShare calls succeeded, want exactly 1", winners, attempts)
		}

		held, err := dep.Store.HeldShare(ctx, seal.ID)
		if err != nil {
			t.Fatalf("HeldShare: %v", err)
		}
		if held.Index() != mine.Index() {
			t.Fatalf("the held share is at index %d, want %d", held.Index(), mine.Index())
		}
	})
}

// ---- fixtures and helpers ----

// testNow is the fixed instant every fixture in this suite counts from,
// already canonical so that nothing has to remember to truncate it. A fixed
// instant rather than time.Now() because a suite whose fixtures move with the
// wall clock is a suite that passes until the day a boundary lands on a
// Tuesday.
func testNow() time.Time {
	return escrow.CanonicalTime(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))
}

// testSchedule is a liveness schedule that validates: three rungs over three
// independent channels, strictly advancing, with a grace period.
func testSchedule() escrow.LivenessSchedule {
	return escrow.LivenessSchedule{
		Since:   testNow(),
		CheckIn: 30 * 24 * time.Hour,
		Escalations: []escrow.Escalation{
			{After: 0, Channel: "email"},
			{After: 7 * 24 * time.Hour, Channel: "sms"},
			{After: 14 * 24 * time.Hour, Channel: "postal"},
		},
		Grace: 14 * 24 * time.Hour,
	}
}

// mustCreate cuts a seal for the deployment's tenant, with the deployment
// itself as the first holder.
func mustCreate(t *testing.T, dep Deployment, required, total int) (escrow.Seal, escrow.SealedKey, []escrow.Share) {
	t.Helper()

	holders := make([]escrow.CustodianID, 0, total)
	for i := range total {
		holders = append(holders, mustCustodian(t, "custodian-"+strconv.Itoa(i)))
	}
	seal, key, shares, err := escrow.Create(dep.Tenant, escrow.Plan{
		Threshold: escrow.Threshold{Required: required, Total: total},
		Holders:   holders,
		System:    holders[0],
		Liveness:  testSchedule(),
	}, escrow.NewFixedClock(testNow()))
	if err != nil {
		t.Fatalf("Create a %d-of-%d seal: %v", required, total, err)
	}
	return seal, key, shares
}

// splitShares separates the share the deployment holds from the rest, by the
// seal's own record of which index is the system custodian's.
func splitShares(t *testing.T, seal escrow.Seal, shares []escrow.Share) (mine escrow.Share, others []escrow.Share) {
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
	if mine.IsZero() {
		t.Fatal("no share was cut at the system custodian's index")
	}
	return mine, others
}

// rebind returns a copy of a share claiming a different seal and generation:
// the forgery a holder of a superseded share would attempt, since the binding
// is unkeyed and an exported share's checksum can be recomputed.
//
// It is the one place this suite reaches past the facade, to
// domain.NewShare — which is legal from inside this module and invisible from
// outside it, and necessary because building a deliberately mis-bound share
// is exactly what the facade does not offer a consumer. Everything else here
// uses facade names so the suite reads the way a consumer's own code reads.
func rebind(t *testing.T, share escrow.Share, seal escrow.SealID, generation escrow.Generation) escrow.Share {
	t.Helper()

	out, err := domain.NewShare(seal, generation, share.Index(), share.Material())
	if err != nil {
		t.Fatalf("rebind a share: %v", err)
	}
	return out
}

func mustSealID(t *testing.T) escrow.SealID {
	t.Helper()

	id, err := escrow.NewSealID(escrow.SystemClock{})
	if err != nil {
		t.Fatalf("NewSealID: %v", err)
	}
	return id
}

func mustTenant(t *testing.T, s string) escrow.TenantID {
	t.Helper()

	id, err := escrow.ParseTenantID(s)
	if err != nil {
		t.Fatalf("ParseTenantID(%q): %v", s, err)
	}
	return id
}

func mustCustodian(t *testing.T, s string) escrow.CustodianID {
	t.Helper()

	id, err := escrow.ParseCustodianID(s)
	if err != nil {
		t.Fatalf("ParseCustodianID(%q): %v", s, err)
	}
	return id
}

func mustProof(t *testing.T, seal escrow.SealID, at time.Time, channel escrow.ChannelID) escrow.ProofOfLife {
	t.Helper()

	id, err := escrow.NewProofID(escrow.SystemClock{})
	if err != nil {
		t.Fatalf("NewProofID: %v", err)
	}
	return escrow.ProofOfLife{Seal: seal, ID: id, At: escrow.CanonicalTime(at), Channel: channel}
}

func testCeremony(
	t *testing.T, dep Deployment, seal escrow.Seal,
	condition escrow.ReleaseConditionKind, outcome escrow.CeremonyOutcome,
	at time.Time, reason string,
) escrow.Ceremony {
	t.Helper()

	id, err := escrow.NewCeremonyID(escrow.SystemClock{})
	if err != nil {
		t.Fatalf("NewCeremonyID: %v", err)
	}
	participants := make([]escrow.CustodianID, 0, len(seal.Custodians))
	for _, c := range seal.Custodians {
		participants = append(participants, c.ID)
	}
	return escrow.Ceremony{
		Tenant:          dep.Tenant,
		ID:              id,
		Seal:            seal.ID,
		Generation:      seal.Generation,
		Condition:       condition,
		Effect:          condition.Effect(),
		Participants:    participants,
		SharesPresented: seal.Threshold.Required,
		SharesRequired:  seal.Threshold.Required,
		Outcome:         outcome,
		Reason:          reason,
		At:              escrow.CanonicalTime(at),
	}
}

// assertSealsEqual compares a stored seal against the one that was written,
// field by field, so that a failure names what drifted rather than printing
// two structs.
func assertSealsEqual(t *testing.T, want, got escrow.Seal) {
	t.Helper()

	if got.Tenant != want.Tenant {
		t.Fatalf("Tenant = %s, want %s", got.Tenant, want.Tenant)
	}
	if got.ID != want.ID {
		t.Fatalf("ID = %s, want %s", got.ID, want.ID)
	}
	if got.Generation != want.Generation {
		t.Fatalf("Generation = %s, want %s", got.Generation, want.Generation)
	}
	if got.Threshold != want.Threshold {
		t.Fatalf("Threshold = %s, want %s", got.Threshold, want.Threshold)
	}
	if !got.Commitment.Equal(want.Commitment) {
		t.Fatalf("Commitment = %s, want %s", got.Commitment, want.Commitment)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("CreatedAt = %s, want %s", got.CreatedAt, want.CreatedAt)
	}
	if !got.SealedAt.Equal(want.SealedAt) {
		t.Fatalf("SealedAt = %s, want %s", got.SealedAt, want.SealedAt)
	}

	if len(got.Custodians) != len(want.Custodians) {
		t.Fatalf("%d custodians, want %d", len(got.Custodians), len(want.Custodians))
	}
	byIndex := make(map[escrow.ShareIndex]escrow.Custodian, len(got.Custodians))
	for _, c := range got.Custodians {
		byIndex[c.Index] = c
	}
	for _, c := range want.Custodians {
		stored, ok := byIndex[c.Index]
		if !ok {
			t.Fatalf("no custodian came back at share index %d", c.Index)
		}
		if stored != c {
			t.Fatalf("custodian at index %d = %+v, want %+v", c.Index, stored, c)
		}
	}

	if got.Liveness.CheckIn != want.Liveness.CheckIn {
		t.Fatalf("CheckIn = %s, want %s", got.Liveness.CheckIn, want.Liveness.CheckIn)
	}
	if got.Liveness.Grace != want.Liveness.Grace {
		t.Fatalf("Grace = %s, want %s", got.Liveness.Grace, want.Liveness.Grace)
	}
	if !got.Liveness.Since.Equal(want.Liveness.Since) {
		t.Fatalf("Liveness.Since = %s, want %s", got.Liveness.Since, want.Liveness.Since)
	}
	if len(got.Liveness.Escalations) != len(want.Liveness.Escalations) {
		t.Fatalf("%d escalations, want %d", len(got.Liveness.Escalations), len(want.Liveness.Escalations))
	}
	for i, e := range want.Liveness.Escalations {
		if got.Liveness.Escalations[i] != e {
			t.Fatalf("escalation %d = %+v, want %+v: the ladder's order is its format", i, got.Liveness.Escalations[i], e)
		}
	}
}

// assertNoSecret fails if text contains any of the secrets, in any encoding a
// careless interpolation would produce, or any of their lengths in decimal.
//
// The public identifiers a rendering is *allowed* to carry — the seal id, the
// generation, the share indices, the threshold — are redacted out before the
// length is searched for, and that is what makes the length assertion mean
// something rather than flake. A minted seal id is 32 random hex characters,
// so roughly one in eight contains the substring "32" somewhere inside an
// identifier the caller already holds. Searching the *remainder* asserts the
// thing actually wanted: that a rendering says nothing beyond the binding it
// is supposed to say.
func assertNoSecret(t *testing.T, label, text string, public []string, secrets ...[]byte) {
	t.Helper()

	remainder := text
	for _, token := range public {
		if token == "" {
			continue
		}
		remainder = strings.ReplaceAll(remainder, token, "<public>")
	}

	for i, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		for encoding, rendered := range map[string]string{
			"raw bytes":       string(secret),
			"lowercase hex":   hex.EncodeToString(secret),
			"uppercase hex":   strings.ToUpper(hex.EncodeToString(secret)),
			"standard base64": base64.StdEncoding.EncodeToString(secret),
			"url base64":      base64.URLEncoding.EncodeToString(secret),
			"go byte slice":   fmt.Sprintf("%v", secret),
			"go hex dump":     fmt.Sprintf("%x", secret),
		} {
			if strings.Contains(text, rendered) {
				t.Fatalf("%s leaked secret %d as %s: %q", label, i, encoding, text)
			}
		}
		if n := strconv.Itoa(len(secret)); strings.Contains(remainder, n) {
			t.Fatalf("%s leaked the length of secret %d (%s): %q\n(with the public identifiers redacted: %q)",
				label, i, n, text, remainder)
		}
	}
}

// publicIdentifiers lists what a seal's renderings and errors are allowed to
// name: the seal, its generation and threshold, and its custodians and their
// share indices. See assertNoSecret.
func publicIdentifiers(seal escrow.Seal) []string {
	out := []string{
		seal.ID.String(), seal.Tenant.String(), seal.Generation.String(),
		seal.Threshold.String(), seal.Commitment.String(),
		strconv.Itoa(seal.Threshold.Required), strconv.Itoa(seal.Threshold.Total),
	}
	for _, c := range seal.Custodians {
		out = append(out, c.ID.String(), c.Holder.String(), strconv.Itoa(int(c.Index)))
	}
	for _, e := range seal.Liveness.Escalations {
		out = append(out, e.Channel.String(), e.After.String(), strconv.FormatInt(int64(e.After), 10))
	}
	out = append(out,
		seal.Liveness.CheckIn.String(), strconv.FormatInt(int64(seal.Liveness.CheckIn), 10),
		seal.Liveness.Grace.String(), strconv.FormatInt(int64(seal.Liveness.Grace), 10),
		seal.Liveness.Since.String(), seal.CreatedAt.String(), seal.SealedAt.String(),
		seal.Liveness.Since.Format(time.RFC3339Nano),
		seal.CreatedAt.Format(time.RFC3339Nano), seal.SealedAt.Format(time.RFC3339Nano),
	)
	return out
}

// destroyAll zeroizes a key and every share, for a test's cleanup. Share
// material left in a test binary's heap is not a vulnerability, but a suite
// that modelled sloppiness would be read as sanctioning it.
func destroyAll(key escrow.SealedKey, shares []escrow.Share) {
	key.Destroy()
	for i := range shares {
		shares[i].Destroy()
	}
}
