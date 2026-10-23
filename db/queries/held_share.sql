-- Queries against escrow.held_share: the single share the deployment holds.
--
-- There are three statements and there is deliberately no UPDATE. A held
-- share is written once and discarded; overwriting it would silently destroy
-- a share a custodian may already have been told the deployment holds, and
-- "replace the share" is not an operation this module offers — the two
-- operations that end a held share's life are a re-seal (which discards it
-- as part of rotating) and a deliberate discard.

-- InsertHeldShare stores the deployment's one share for a seal.
--
-- There is no ON CONFLICT clause, and its absence is the mechanism rather
-- than an oversight. The table's primary key is (tenant_id, seal_id), so a
-- second share for one seal raises a unique violation (SQLSTATE 23505),
-- which internal/pgstore maps onto domain.ErrShareAlreadyHeld —
-- CHARTER.md's first safety property. An ON CONFLICT DO NOTHING would turn
-- that refusal into a silent no-op, and an ON CONFLICT DO UPDATE would turn
-- it into the overwrite described above. The constraint is also what makes
-- the refusal hold against a concurrent transaction, where a
-- read-then-insert in Go would not.
--
-- The foreign key is the second refusal in this one statement: a share for a
-- seal that is not stored raises 23503, which the adapter maps onto
-- domain.ErrSealNotFound.
--
-- name: InsertHeldShare :exec
INSERT INTO escrow.held_share (tenant_id, seal_id, generation, share_index, material)
VALUES (@tenant_id, @seal_id, @generation, @share_index, @material);

-- HeldShare reads the deployment's share. No row means the deployment holds
-- none, which is an ordinary state and not an error: a seal every one of
-- whose shares went to an external custodian is a stronger seal, and its
-- dead-man's switch is informational rather than share-releasing. The
-- adapter maps pgx.ErrNoRows onto domain.ErrNoHeldShare.
--
-- name: HeldShare :one
SELECT generation, share_index, material
FROM escrow.held_share
WHERE tenant_id = @tenant_id AND seal_id = @seal_id;

-- DeleteHeldShare discards the deployment's share and reports whether there
-- was one, so that a discard of nothing is distinguishable from a discard of
-- something. Used both by a deliberate discard and by the re-seal path,
-- where it runs in the same transaction as the generation advance — see
-- UpdateSealToNextGeneration.
--
-- A DELETE does not zeroize the bytes on disk; Postgres leaves the old tuple
-- for VACUUM. That is a property of the storage engine rather than of this
-- statement, and it is one of the reasons the table's comment puts
-- storage-level encryption on the deployment. The in-memory adapter's
-- Destroy does zeroize, and the conformance suite asserts the observable
-- contract both share: after a discard, no share is held.
--
-- name: DeleteHeldShare :execrows
DELETE FROM escrow.held_share
WHERE tenant_id = @tenant_id AND seal_id = @seal_id;
