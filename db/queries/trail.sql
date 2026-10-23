-- Queries against escrow.proof_of_life and escrow.ceremony: the records a
-- human reads when deciding whether a lapse was a false positive, and the
-- record of every ceremony including the ones that were refused.

-- InsertProofOfLife records a proof of life, reporting how many rows it
-- wrote.
--
-- ON CONFLICT DO NOTHING plus the row count is how a *retry* is told from a
-- *conflict*: the channels a proof arrives on redeliver, so recording the
-- same proof twice must be one proof and not an error, while the same id
-- carrying a different instant or channel is a bug or a forgery and must be
-- refused rather than silently resolved in favour of one of the two. Zero
-- rows means the id was already there, and the adapter then reads the stored
-- proof and compares it — see ProofOfLife below.
--
-- name: InsertProofOfLife :execrows
INSERT INTO escrow.proof_of_life (tenant_id, seal_id, proof_id, observed_at, channel)
VALUES (@tenant_id, @seal_id, @proof_id, @observed_at, @channel)
ON CONFLICT (tenant_id, seal_id, proof_id) DO NOTHING;

-- ProofOfLife reads one proof by id, for the comparison InsertProofOfLife's
-- zero-row case requires.
--
-- name: ProofOfLife :one
SELECT observed_at, channel
FROM escrow.proof_of_life
WHERE tenant_id = @tenant_id AND seal_id = @seal_id AND proof_id = @proof_id;

-- ProofsOfLife reads every proof of life for a seal, oldest first, breaking
-- ties by id so the order is total and identical on every adapter.
--
-- Ascending rather than the index's descending order, because the
-- conformance suite and the liveness evaluation both want chronological
-- order and reversing a list in Go is cheaper than a second index. Every
-- proof is returned rather than a page: Evaluate needs only the most recent,
-- but the pattern is what a human investigating a lapse needs, and that is
-- what this record exists for.
--
-- name: ProofsOfLife :many
SELECT proof_id, observed_at, channel
FROM escrow.proof_of_life
WHERE tenant_id = @tenant_id AND seal_id = @seal_id
ORDER BY observed_at, proof_id;

-- InsertCeremony records one ceremony, reporting how many rows it wrote.
--
-- The same retry-versus-conflict treatment as InsertProofOfLife, for the
-- same reason: a caller retrying after a transient failure must not create a
-- second record of one ceremony.
--
-- The schema's effect CHECK is what refuses a record claiming that a
-- liveness lapse unsealed something — CHARTER.md's second safety property,
-- in the catalog.
--
-- name: InsertCeremony :execrows
INSERT INTO escrow.ceremony (
    tenant_id, ceremony_id, seal_id, generation, release_condition, effect,
    participants, shares_presented, shares_required, outcome, reason, concluded_at
) VALUES (
    @tenant_id, @ceremony_id, @seal_id, @generation, @release_condition, @effect,
    @participants, @shares_presented, @shares_required, @outcome, @reason, @concluded_at
)
ON CONFLICT (tenant_id, ceremony_id) DO NOTHING;

-- Ceremony reads one ceremony by id, for the comparison InsertCeremony's
-- zero-row case requires.
--
-- name: Ceremony :one
SELECT seal_id, generation, release_condition, effect, participants,
       shares_presented, shares_required, outcome, reason, concluded_at
FROM escrow.ceremony
WHERE tenant_id = @tenant_id AND ceremony_id = @ceremony_id;

-- Ceremonies reads every ceremony for a seal, oldest first, breaking ties by
-- id.
--
-- The refusals and the failures come back with the completions, and that is
-- the point — CHARTER.md: the failed ones "are the interesting signal". A
-- predicate restricting this to outcome = 'completed' would be the single
-- most damaging thing anybody could add to this file.
--
-- name: Ceremonies :many
SELECT ceremony_id, generation, release_condition, effect, participants,
       shares_presented, shares_required, outcome, reason, concluded_at
FROM escrow.ceremony
WHERE tenant_id = @tenant_id AND seal_id = @seal_id
ORDER BY concluded_at, ceremony_id;
