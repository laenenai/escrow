-- Queries against escrow.seal, escrow.custodian and escrow.escalation: the
-- current custody arrangement.
--
-- The three tables are read and written together, always, because they are
-- one value — a domain.Seal carries the threshold, the custodian list and
-- the liveness schedule, and a seal read with two of the three is not a
-- seal. internal/pgstore does every one of these inside a transaction for
-- that reason.

-- InsertSeal writes the seal row. The schema's own CHECK constraints are the
-- second line of defence behind domain.Seal.Validate, and they are the line
-- that holds against a hand-written INSERT: threshold_required >= 2 is
-- CHARTER.md's first safety property in the catalog.
--
-- name: InsertSeal :exec
INSERT INTO escrow.seal (
    tenant_id, seal_id, generation, threshold_required, threshold_total,
    commitment, check_in_ns, grace_ns, liveness_since, created_at, sealed_at
) VALUES (
    @tenant_id, @seal_id, @generation, @threshold_required, @threshold_total,
    @commitment, @check_in_ns, @grace_ns, @liveness_since, @created_at, @sealed_at
);

-- Seal reads one seal's own row. tenant_id is not returned: the store is
-- scoped to one tenant and the value is already in the WHERE clause, so
-- selecting it would be asking the database to confirm a value we used to
-- find the row.
--
-- name: Seal :one
SELECT generation, threshold_required, threshold_total, commitment,
       check_in_ns, grace_ns, liveness_since, created_at, sealed_at
FROM escrow.seal
WHERE tenant_id = @tenant_id AND seal_id = @seal_id;

-- UpdateSealToNextGeneration advances a seal to a new generation and reports
-- how many rows it moved.
--
-- The WHERE clause names the generation the seal was expected to be at, as
-- `sqlc.arg(generation) - 1`, so a caller that is told zero rows moved knows
-- either that the seal is absent or that its generation did not follow —
-- and must fail the re-seal rather than guess. That predicate is what makes
-- the rotation safe without a row lock: two concurrent rotations to the same
-- new generation cannot both succeed.
--
-- The generation appears twice, which is why this statement uses sqlc.arg()
-- rather than the @name shorthand the rest of this file uses: sqlc v1.30.0
-- collapses repeated sqlc.arg() references to one parameter and does **not**
-- collapse repeated @name ones, which would generate a params struct with
-- two fields called Generation. Keeping the arithmetic in the SQL also keeps
-- the "it was not at N-1" reasoning where it is reviewed.
--
-- created_at is deliberately not in the SET list. A re-seal keeps the seal's
-- creation instant; only this generation's sealed_at moves.
--
-- name: UpdateSealToNextGeneration :execrows
UPDATE escrow.seal
SET generation = sqlc.arg(generation),
    threshold_required = sqlc.arg(threshold_required),
    threshold_total = sqlc.arg(threshold_total),
    commitment = sqlc.arg(commitment),
    check_in_ns = sqlc.arg(check_in_ns),
    grace_ns = sqlc.arg(grace_ns),
    liveness_since = sqlc.arg(liveness_since),
    sealed_at = sqlc.arg(sealed_at)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND seal_id = sqlc.arg(seal_id)
  AND generation = sqlc.arg(generation) - 1;

-- InsertCustodian writes one custodian row. A seal has exactly
-- threshold_total of them, and the partial unique index
-- custodian_one_system_holder_per_seal is what refuses a second custodian of
-- kind 'system' — CHARTER.md's first safety property, enforced by the
-- catalog rather than by this statement.
--
-- name: InsertCustodian :exec
INSERT INTO escrow.custodian (tenant_id, seal_id, custodian_id, holder, share_index)
VALUES (@tenant_id, @seal_id, @custodian_id, @holder, @share_index);

-- Custodians reads a seal's custodian list.
--
-- Ordered by share_index so the list is in a stable order on every read.
-- The order is not meaningful — an index is an x-coordinate chosen by the
-- splitter, not an ordinal — but a stable one is what lets the conformance
-- suite compare a stored seal against the one that was written without
-- sorting first.
--
-- name: Custodians :many
SELECT custodian_id, holder, share_index
FROM escrow.custodian
WHERE tenant_id = @tenant_id AND seal_id = @seal_id
ORDER BY share_index;

-- DeleteCustodians removes a seal's whole custodian list, for the delete-then
-- -insert a re-seal performs inside one transaction. Changing custodians is
-- one of the reasons to re-seal, so the new generation's list is written
-- wholesale rather than diffed: a diff would have to decide what a custodian
-- who kept their place but changed index means, and the answer is "they hold
-- a different share now", which is a replacement.
--
-- name: DeleteCustodians :exec
DELETE FROM escrow.custodian
WHERE tenant_id = @tenant_id AND seal_id = @seal_id;

-- InsertEscalation writes one stage of the notification ladder.
--
-- name: InsertEscalation :exec
INSERT INTO escrow.escalation (tenant_id, seal_id, stage, after_ns, channel)
VALUES (@tenant_id, @seal_id, @stage, @after_ns, @channel);

-- Escalations reads a seal's notification ladder in stage order. The order is
-- the format: stage 2 means the second rung, and the offsets strictly
-- increase.
--
-- name: Escalations :many
SELECT stage, after_ns, channel
FROM escrow.escalation
WHERE tenant_id = @tenant_id AND seal_id = @seal_id
ORDER BY stage;

-- DeleteEscalations removes a seal's whole ladder, for the same
-- delete-then-insert a re-seal performs.
--
-- name: DeleteEscalations :exec
DELETE FROM escrow.escalation
WHERE tenant_id = @tenant_id AND seal_id = @seal_id;
