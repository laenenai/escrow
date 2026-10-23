package sealstore

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/laenenai/escrow/internal/domain"
)

// memoryStore is the in-memory SealStore: four maps behind a mutex. It is
// the adapter the core is unit-tested against and the reference an adapter
// author reads to see what the suite actually demands. It is not a
// production store — nothing in it survives the process, and a seal whose
// only record was in a process that exited is a seal nobody can run a
// ceremony against.
//
// The one-share invariant is a property of the data structure here rather
// than of the code: held is a map from seal to **one** share, so there is no
// representation in which the deployment holds two. The Postgres adapter
// gets the same property from a primary key. Neither adapter has a code path
// that could hold a second share incorrectly, because neither has a place to
// put one.
//
// The mutex is held across each whole method rather than only across the map
// write. HoldShare has to read the seal, check the generation and the
// custodian index, check that no share is held, and then write — and two
// callers interleaving those steps are exactly how a store ends up holding
// two shares. ConcurrentHoldShareYieldsOneWinner in the suite is that
// requirement as a test.
type memoryStore struct {
	tenant domain.TenantID

	mu         sync.Mutex
	seals      map[domain.SealID]domain.Seal
	held       map[domain.SealID]domain.Share
	proofs     map[domain.SealID][]domain.ProofOfLife
	ceremonies map[domain.SealID][]domain.Ceremony
}

var _ SealStore = (*memoryStore)(nil)

// MemoryConfig configures NewMemory.
type MemoryConfig struct {
	// Tenant is the tenant this store is scoped to. Required: every record
	// in it is tenant-scoped, and a store with no tenant could hold a seal
	// whose tenant nothing ever checked.
	//
	// Unlike audit's in-memory log, which accepts the unnamed chain because
	// it holds exactly one chain and never has to tell two apart, this one
	// does check: CreateSeal refuses a seal belonging to another tenant, and
	// a test that passes a store the wrong tenant's seal should find out
	// here rather than against Postgres.
	Tenant domain.TenantID
}

// NewMemory returns an in-memory SealStore scoped to cfg.Tenant.
//
// It returns an error, where audit's NewMemory does not, because this
// config has a required field. A constructor that accepted a zero tenant and
// then refused every seal would move the failure from the wiring to the
// first call.
func NewMemory(cfg MemoryConfig) (SealStore, error) {
	if cfg.Tenant.IsZero() {
		return nil, fmt.Errorf("%w: sealstore: Tenant is required", domain.ErrInvalidConfig)
	}
	return &memoryStore{
		tenant:     cfg.Tenant,
		seals:      make(map[domain.SealID]domain.Seal),
		held:       make(map[domain.SealID]domain.Share),
		proofs:     make(map[domain.SealID][]domain.ProofOfLife),
		ceremonies: make(map[domain.SealID][]domain.Ceremony),
	}, nil
}

// CreateSeal implements SealStore.
func (s *memoryStore) CreateSeal(ctx context.Context, seal domain.Seal) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: create seal: %w", err)
	}
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

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.seals[seal.ID]; exists {
		return fmt.Errorf("escrow: create seal %s: %w", seal.ID, domain.ErrSealExists)
	}
	s.seals[seal.ID] = seal.Clone()
	return nil
}

// Seal implements SealStore.
func (s *memoryStore) Seal(ctx context.Context, id domain.SealID) (domain.Seal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Seal{}, fmt.Errorf("escrow: read seal: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seal, ok := s.seals[id]
	if !ok {
		return domain.Seal{}, fmt.Errorf("escrow: read seal %s: %w", id, domain.ErrSealNotFound)
	}
	return seal.Clone(), nil
}

// ReplaceSeal implements SealStore. The discard of the held share is in the
// same critical section as the replacement, which is the whole reason the
// two are one method: see this package's doc comment.
func (s *memoryStore) ReplaceSeal(ctx context.Context, seal domain.Seal) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: replace seal: %w", err)
	}
	if err := seal.Validate(); err != nil {
		return fmt.Errorf("escrow: replace seal: %w", err)
	}
	if seal.Tenant != s.tenant {
		return fmt.Errorf("escrow: replace seal: %w: seal belongs to another tenant", domain.ErrInvalidArgument)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.seals[seal.ID]
	if !ok {
		return fmt.Errorf("escrow: replace seal %s: %w", seal.ID, domain.ErrSealNotFound)
	}
	if want := current.Generation.Next(); seal.Generation != want {
		return fmt.Errorf("escrow: replace seal %s: %w: generation %s does not follow the stored %s",
			seal.ID, domain.ErrInvalidArgument, seal.Generation, current.Generation)
	}
	if !seal.CreatedAt.Equal(current.CreatedAt) {
		return fmt.Errorf("escrow: replace seal %s: %w: a re-seal keeps the seal's creation instant",
			seal.ID, domain.ErrInvalidArgument)
	}

	s.seals[seal.ID] = seal.Clone()
	if held, ok := s.held[seal.ID]; ok {
		held.Destroy()
		delete(s.held, seal.ID)
	}
	return nil
}

// HoldShare implements SealStore.
func (s *memoryStore) HoldShare(ctx context.Context, share domain.Share) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: hold share: %w", err)
	}
	if err := share.Validate(); err != nil {
		return fmt.Errorf("escrow: hold share: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seal, ok := s.seals[share.Seal()]
	if !ok {
		return fmt.Errorf("escrow: hold share for seal %s: %w", share.Seal(), domain.ErrSealNotFound)
	}
	if err := checkShareFitsSeal(seal, share); err != nil {
		return err
	}
	if _, exists := s.held[share.Seal()]; exists {
		return fmt.Errorf("escrow: hold share for seal %s: %w", share.Seal(), domain.ErrShareAlreadyHeld)
	}

	// Copied through the only constructor, so the store's share does not
	// share a backing array with the caller's: a caller that destroys its
	// own copy immediately — which it should — must not destroy the store's.
	stored, err := domain.NewShare(share.Seal(), share.Generation(), share.Index(), share.Material())
	if err != nil {
		return fmt.Errorf("escrow: hold share for seal %s: %w", share.Seal(), err)
	}
	s.held[share.Seal()] = stored
	return nil
}

// HeldShare implements SealStore.
func (s *memoryStore) HeldShare(ctx context.Context, id domain.SealID) (domain.Share, error) {
	if err := ctx.Err(); err != nil {
		return domain.Share{}, fmt.Errorf("escrow: read held share: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	held, ok := s.held[id]
	if !ok {
		return domain.Share{}, fmt.Errorf("escrow: read held share for seal %s: %w", id, domain.ErrNoHeldShare)
	}
	// A copy, so a caller that destroys what it was given does not zeroize
	// the share the deployment still holds.
	return domain.NewShare(held.Seal(), held.Generation(), held.Index(), held.Material())
}

// DiscardHeldShare implements SealStore.
func (s *memoryStore) DiscardHeldShare(ctx context.Context, id domain.SealID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: discard held share: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	held, ok := s.held[id]
	if !ok {
		return fmt.Errorf("escrow: discard held share for seal %s: %w", id, domain.ErrNoHeldShare)
	}
	held.Destroy()
	delete(s.held, id)
	return nil
}

// RecordProofOfLife implements SealStore.
func (s *memoryStore) RecordProofOfLife(ctx context.Context, proof domain.ProofOfLife) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: record proof of life: %w", err)
	}
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("escrow: record proof of life: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seals[proof.Seal]; !ok {
		return fmt.Errorf("escrow: record proof of life for seal %s: %w", proof.Seal, domain.ErrSealNotFound)
	}
	for _, existing := range s.proofs[proof.Seal] {
		if existing.ID != proof.ID {
			continue
		}
		if existing.At.Equal(proof.At) && existing.Channel == proof.Channel {
			// A retried delivery of the same proof. One proof, no error.
			return nil
		}
		return fmt.Errorf("escrow: record proof of life %s for seal %s: %w: a proof with that id is already recorded with different content",
			proof.ID, proof.Seal, domain.ErrInvalidArgument)
	}
	s.proofs[proof.Seal] = append(s.proofs[proof.Seal], proof)
	return nil
}

// ProofsOfLife implements SealStore.
func (s *memoryStore) ProofsOfLife(ctx context.Context, id domain.SealID) ([]domain.ProofOfLife, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("escrow: read proofs of life: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seals[id]; !ok {
		return nil, fmt.Errorf("escrow: read proofs of life for seal %s: %w", id, domain.ErrSealNotFound)
	}

	out := slices.Clone(s.proofs[id])
	slices.SortFunc(out, func(a, b domain.ProofOfLife) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return cmpString(a.ID.String(), b.ID.String())
	})
	return out, nil
}

// RecordCeremony implements SealStore.
func (s *memoryStore) RecordCeremony(ctx context.Context, ceremony domain.Ceremony) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("escrow: record ceremony: %w", err)
	}
	if err := ceremony.Validate(); err != nil {
		return fmt.Errorf("escrow: record ceremony: %w", err)
	}
	if ceremony.Tenant != s.tenant {
		return fmt.Errorf("escrow: record ceremony: %w: ceremony belongs to another tenant", domain.ErrInvalidArgument)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	seal, ok := s.seals[ceremony.Seal]
	if !ok {
		return fmt.Errorf("escrow: record ceremony for seal %s: %w", ceremony.Seal, domain.ErrSealNotFound)
	}
	if ceremony.Generation > seal.Generation {
		return fmt.Errorf("escrow: record ceremony for seal %s: %w: ceremony is at %s, ahead of the seal's %s",
			ceremony.Seal, domain.ErrInvalidArgument, ceremony.Generation, seal.Generation)
	}
	for _, existing := range s.ceremonies[ceremony.Seal] {
		if existing.ID != ceremony.ID {
			continue
		}
		if sameCeremony(existing, ceremony) {
			return nil
		}
		return fmt.Errorf("escrow: record ceremony %s for seal %s: %w: a ceremony with that id is already recorded with different content",
			ceremony.ID, ceremony.Seal, domain.ErrInvalidArgument)
	}
	s.ceremonies[ceremony.Seal] = append(s.ceremonies[ceremony.Seal], ceremony.Clone())
	return nil
}

// Ceremonies implements SealStore.
func (s *memoryStore) Ceremonies(ctx context.Context, id domain.SealID) ([]domain.Ceremony, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("escrow: read ceremonies: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.seals[id]; !ok {
		return nil, fmt.Errorf("escrow: read ceremonies for seal %s: %w", id, domain.ErrSealNotFound)
	}

	out := make([]domain.Ceremony, 0, len(s.ceremonies[id]))
	for _, c := range s.ceremonies[id] {
		out = append(out, c.Clone())
	}
	slices.SortFunc(out, func(a, b domain.Ceremony) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return cmpString(a.ID.String(), b.ID.String())
	})
	return out, nil
}

// checkShareFitsSeal is the three preconditions on a share the deployment is
// about to hold, each of which is a charter property rather than a
// convenience. It is shared by both adapters' HoldShare — the Postgres one
// runs it inside the same transaction as the insert — so that neither can
// drift from the suite.
func checkShareFitsSeal(seal domain.Seal, share domain.Share) error {
	if share.Generation() != seal.Generation {
		return fmt.Errorf("escrow: hold share for seal %s: %w: share is %s, the seal is at %s",
			seal.ID, domain.ErrForeignShare, share.Generation(), seal.Generation)
	}
	system, ok := seal.SystemCustodian()
	if !ok {
		return fmt.Errorf("escrow: hold share for seal %s: %w: the seal names no custodian inside the deployment, so the deployment holds no share of it",
			seal.ID, domain.ErrInvalidArgument)
	}
	if share.Index() != system.Index {
		return fmt.Errorf("escrow: hold share for seal %s: %w: share index %d is custodian %s's, not the deployment's",
			seal.ID, domain.ErrInvalidArgument, share.Index(), custodianAt(seal, share.Index()))
	}
	return nil
}

// custodianAt names whoever holds the share at index, for an error message
// that tells an operator whose share was nearly stored in the wrong place.
// It returns a placeholder rather than failing when the index belongs to
// nobody, because the caller is already constructing an error.
func custodianAt(seal domain.Seal, index domain.ShareIndex) string {
	if c, ok := seal.Custodian(index); ok {
		return c.ID.String()
	}
	return "nobody"
}

// sameCeremony reports whether two ceremony records are field-for-field
// identical, which is what makes re-recording one a no-op rather than a
// conflict.
func sameCeremony(a, b domain.Ceremony) bool {
	if a.Tenant != b.Tenant || a.Seal != b.Seal || a.Generation != b.Generation ||
		a.Condition != b.Condition || a.Effect != b.Effect ||
		a.SharesPresented != b.SharesPresented || a.SharesRequired != b.SharesRequired ||
		a.Outcome != b.Outcome || a.Reason != b.Reason || !a.At.Equal(b.At) {
		return false
	}
	return slices.Equal(a.Participants, b.Participants)
}

// cmpString is strings.Compare without the import, kept here so the two
// ordering functions above read identically.
func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
