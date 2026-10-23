-- 00001_escrow.sql is the whole of this module's fixed schema.
--
-- Two things are deliberately **not** in this file, and both are decisions
-- rather than omissions:
--
--   * The row-level-security policies. They are applied by internal/migrate
--     through tenancy.EnableRLS on every Up, not written out here. A live
--     cross-tenant disclosure was found in this project on 2026-10-23: a
--     tenant policy created AS PERMISSIVE is OR-ed away by any later
--     permissive policy on the same table, and any table owner can add one.
--     tenancy.EnableRLS installs the correct restrictive-plus-permissive
--     pair, is idempotent, and *repairs* a policy whose predicate has
--     drifted. Hand-written policies in a versioned migration can do none of
--     those three things: a migration that has already been applied is never
--     re-run, so a deployment whose policies were weakened would stay
--     weakened while goose reported everything applied.
--   * The application role's grants. The role's name is configuration — see
--     internal/migrate's Config.AppRole — so the GRANT has to be composed at
--     run time and reconciled on every Up for the same reason.
--
-- # This schema is mutable, and that is not a contradiction
--
-- audit's schema revokes UPDATE and DELETE and refuses them with a trigger,
-- because an audit history that can be rewritten is not an audit history.
-- Nothing of that kind is here, and the distinction matters: **this module's
-- tables are mutable by design.** A seal is re-sealed (a new generation, a
-- new commitment, new custodians); the deployment's single share is
-- discarded when it rotates or when the deployment hands it to a human. A
-- schema that forbade those would forbid CHARTER.md's fourth safety
-- property.
--
-- The append-only, tamper-evident record of what happened lives in `audit`,
-- in audit's own schema, under audit's own privilege separation — see
-- internal/trail. So the honest statement of what this schema guarantees is:
-- the *current* custody arrangement, with the one-share invariant enforced
-- structurally, and no claim at all about history. History is audit's.

-- +goose Up
CREATE SCHEMA IF NOT EXISTS escrow;

-- escrow.seal is one row per seal: the current custody arrangement. A
-- re-seal UPDATEs it in place rather than inserting a new row, because the
-- seal id is what every distributed share is bound to and a second row for
-- one seal id would be a second answer to "what threshold is this seal at".
--
-- The liveness schedule's two durations are bigint nanosecond counts rather
-- than `interval`. A Go time.Duration *is* an int64 nanosecond count, so a
-- bigint round-trips it exactly; an interval holds microseconds plus
-- separate month and day components whose comparison semantics depend on a
-- calendar, which is the wrong model for "how long is a proof of life good
-- for" and would make equality assertions in the conformance suite
-- approximate.
--
-- There is no key column and there never will be. The key this record
-- describes exists only as shares.
CREATE TABLE escrow.seal (
    tenant_id          text        NOT NULL,
    seal_id            text        NOT NULL CHECK (seal_id ~ '^[0-9a-f]{32}$'),
    generation         bigint      NOT NULL CHECK (generation >= 1),
    -- The lower bound on threshold_required is CHARTER.md's first safety
    -- property in the schema, not merely in Go: the deployment may hold one
    -- share, so a seal requiring one share would be a seal the deployment
    -- could open alone. The upper bound on threshold_total is GF(256)'s —
    -- the polynomial is evaluated at x = 1..255 and there is no 256th
    -- distinct point.
    threshold_required integer     NOT NULL CHECK (threshold_required >= 2),
    threshold_total    integer     NOT NULL CHECK (threshold_total >= threshold_required
                                                   AND threshold_total <= 255),
    commitment         bytea       NOT NULL CHECK (octet_length(commitment) = 32),
    check_in_ns        bigint      NOT NULL CHECK (check_in_ns > 0),
    -- A zero grace period is a switch that fires on the same instant as its
    -- final warning, which is a warning nobody can act on.
    grace_ns           bigint      NOT NULL CHECK (grace_ns > 0),
    liveness_since     timestamptz NOT NULL,
    created_at         timestamptz NOT NULL,
    sealed_at          timestamptz NOT NULL CHECK (sealed_at >= created_at),
    PRIMARY KEY (tenant_id, seal_id)
);

COMMENT ON TABLE escrow.seal IS
    'One row per seal: the current custody arrangement — threshold, key commitment, '
    'and liveness schedule. Re-sealing updates the row in place. There is no key '
    'column: the key exists only as shares.';

-- escrow.custodian names who holds which share. One row per share, so the
-- distribution of a seal's shares is readable as rows rather than inferred.
CREATE TABLE escrow.custodian (
    tenant_id    text     NOT NULL,
    seal_id      text     NOT NULL,
    custodian_id text     NOT NULL,
    holder       text     NOT NULL CHECK (holder IN ('external', 'system')),
    -- share_index is the x-coordinate of the share's point, which the
    -- splitter chooses: it is NOT an ordinal 1..threshold_total, and a
    -- measured 5-share split produced [227 56 135 108 210]. Index 0 is
    -- excluded because the polynomial's value at zero is the secret itself.
    share_index  smallint NOT NULL CHECK (share_index BETWEEN 1 AND 255),
    PRIMARY KEY (tenant_id, seal_id, custodian_id),
    -- One custodian per share: a threshold counts distinct custodians, so
    -- one person holding two shares would be one person holding two votes.
    UNIQUE (tenant_id, seal_id, share_index),
    FOREIGN KEY (tenant_id, seal_id)
        REFERENCES escrow.seal (tenant_id, seal_id) ON DELETE CASCADE
);

-- CHARTER.md's first safety property, in the catalog: at most one of a
-- seal's custodians may be the deployment itself. A partial unique index is
-- the only way to say "at most one row matching this predicate per group" in
-- Postgres, and saying it here means no application bug, no concurrent
-- transaction and no hand-written UPDATE can produce a seal with two shares
-- inside the deployment.
CREATE UNIQUE INDEX custodian_one_system_holder_per_seal
    ON escrow.custodian (tenant_id, seal_id)
    WHERE holder = 'system';

COMMENT ON INDEX escrow.custodian_one_system_holder_per_seal IS
    'CHARTER.md safety property 1: at most one of a seal''s shares may be held '
    'inside the deployment. Enforced here so that no application path can create '
    'a seal the deployment could open alone.';

-- escrow.escalation is the notification ladder, one row per stage. It is a
-- table rather than an array column because the stage order is load-bearing
-- (it is what "stage 2 of 3" means in a log line and in the attempt trail)
-- and because a stage is two values, an offset and a channel, which an array
-- would have to pack.
CREATE TABLE escrow.escalation (
    tenant_id text   NOT NULL,
    seal_id   text   NOT NULL,
    stage     integer NOT NULL CHECK (stage >= 1),
    after_ns  bigint NOT NULL CHECK (after_ns >= 0),
    channel   text   NOT NULL CHECK (channel <> ''),
    PRIMARY KEY (tenant_id, seal_id, stage),
    FOREIGN KEY (tenant_id, seal_id)
        REFERENCES escrow.seal (tenant_id, seal_id) ON DELETE CASCADE
);

-- escrow.held_share is the single share the deployment holds for a seal.
--
-- **The primary key is (tenant_id, seal_id), and that is the point of this
-- table's design.** CHARTER.md's first safety property is that the system
-- holds at most one share; here a second row for one seal does not exist as
-- a representable state. Not "is rejected by a check" — cannot exist. A
-- second HoldShare raises a unique violation, which the adapter maps onto
-- ErrShareAlreadyHeld, and it does so whether the second attempt came from
-- another goroutine, another process, or a hand-written INSERT.
--
-- The material column holds actual share bytes, and it is the only column in
-- this schema that does. Two consequences the deployment owns rather than
-- this module:
--
--   * Storage-level encryption of this table (or of the database) is the
--     deployment's responsibility. This module's guarantee is that one share
--     is never sufficient, not that one share is unreadable by whoever holds
--     the disk.
--   * No error raised by the adapter may carry this column's content. The
--     adapter maps a SQLSTATE onto a sentinel and drops everything Postgres
--     said, because Postgres echoes offending values into some of its
--     messages.
CREATE TABLE escrow.held_share (
    tenant_id   text        NOT NULL,
    seal_id     text        NOT NULL,
    generation  bigint      NOT NULL CHECK (generation >= 1),
    share_index smallint    NOT NULL CHECK (share_index BETWEEN 1 AND 255),
    material    bytea       NOT NULL CHECK (octet_length(material) = 32),
    held_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, seal_id),
    FOREIGN KEY (tenant_id, seal_id)
        REFERENCES escrow.seal (tenant_id, seal_id) ON DELETE CASCADE
);

COMMENT ON TABLE escrow.held_share IS
    'The single share the deployment holds for a seal. The primary key is '
    '(tenant_id, seal_id), so CHARTER.md safety property 1 — at most one share — '
    'is not a representable violation. The material column is the only share '
    'material in this schema; no error may reproduce it.';

-- escrow.proof_of_life is the append-only-in-practice record the liveness
-- state machine reads. Every proof is kept, not just the most recent one:
-- Evaluate needs only the latest, but a human deciding whether a lapse was a
-- false positive needs the pattern, and that is the question this record
-- exists to answer.
CREATE TABLE escrow.proof_of_life (
    tenant_id   text        NOT NULL,
    seal_id     text        NOT NULL,
    proof_id    text        NOT NULL CHECK (proof_id ~ '^[0-9a-f]{32}$'),
    observed_at timestamptz NOT NULL,
    channel     text        NOT NULL CHECK (channel <> ''),
    PRIMARY KEY (tenant_id, seal_id, proof_id),
    FOREIGN KEY (tenant_id, seal_id)
        REFERENCES escrow.seal (tenant_id, seal_id) ON DELETE CASCADE
);

-- The read path is "this seal's proofs, newest first", which is the whole
-- query the liveness evaluation and every human investigation make.
CREATE INDEX proof_of_life_by_time
    ON escrow.proof_of_life (tenant_id, seal_id, observed_at DESC);

-- escrow.ceremony is CHARTER.md's "released only under a recorded ceremony",
-- as rows — including the refusals and the failures, which are the
-- interesting signal.
--
-- It records the arrangement as it was (generation, shares_required) rather
-- than only a reference to the seal, because a seal is re-sealed and a
-- ceremony is not: a reader three years later must be able to see how many
-- shares were required *then*.
CREATE TABLE escrow.ceremony (
    tenant_id         text        NOT NULL,
    ceremony_id       text        NOT NULL CHECK (ceremony_id ~ '^[0-9a-f]{32}$'),
    seal_id           text        NOT NULL,
    generation        bigint      NOT NULL CHECK (generation >= 1),
    release_condition text        NOT NULL CHECK (release_condition IN
                                      ('human_act', 'threshold_reached', 'liveness_lapse')),
    -- The effect is stored rather than derived, so the record stays readable
    -- if the mapping ever changes: a historical record must say what
    -- happened, not what today's code would do. The CHECK is the mapping as
    -- of this migration, and it is the schema's statement of CHARTER.md's
    -- second safety property — a liveness lapse cannot be recorded as having
    -- unsealed anything.
    effect            text        NOT NULL,
    -- Named explicitly rather than left to Postgres, because it is commented
    -- below and a generated name for a constraint spanning two columns is not
    -- the one anybody would guess.
    CONSTRAINT ceremony_effect_matches_condition CHECK (
        (release_condition = 'threshold_reached' AND effect = 'unseal')
        OR (release_condition IN ('human_act', 'liveness_lapse') AND effect = 'share')),
    participants      text[]      NOT NULL CHECK (cardinality(participants) >= 1),
    shares_presented  integer     NOT NULL CHECK (shares_presented >= 0),
    shares_required   integer     NOT NULL CHECK (shares_required >= 0),
    outcome           text        NOT NULL CHECK (outcome IN ('completed', 'refused', 'failed')),
    reason            text        NOT NULL DEFAULT '',
    concluded_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, ceremony_id),
    FOREIGN KEY (tenant_id, seal_id)
        REFERENCES escrow.seal (tenant_id, seal_id) ON DELETE CASCADE
);

COMMENT ON CONSTRAINT ceremony_effect_matches_condition ON escrow.ceremony IS
    'CHARTER.md safety property 2: a liveness lapse releases a share, never the '
    'content. Only threshold_reached — whose precondition is that the threshold '
    'has already been reached — may be recorded with effect = unseal.';

CREATE INDEX ceremony_by_seal
    ON escrow.ceremony (tenant_id, seal_id, concluded_at DESC);

-- +goose Down
DROP TABLE IF EXISTS escrow.ceremony;

DROP TABLE IF EXISTS escrow.proof_of_life;

DROP TABLE IF EXISTS escrow.held_share;

DROP TABLE IF EXISTS escrow.escalation;

DROP TABLE IF EXISTS escrow.custodian;

DROP TABLE IF EXISTS escrow.seal;

-- The schema itself is not dropped: goose's own version table for this
-- module lives in it (escrow.goose_db_version), so dropping the schema here
-- would delete the bookkeeping recording that this very migration was rolled
-- back. The application role is not dropped either — roles are cluster-wide
-- rather than per-database, so dropping one would break every other database
-- on the same cluster that still uses it.
