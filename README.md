# escrow

[![ci](https://github.com/laenenai/escrow/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/escrow/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/escrow.svg)](https://pkg.go.dev/github.com/laenenai/escrow)

Seals a key under M-of-N shares held by named custodians, and releases it only
under a recorded ceremony — by human act, by threshold, or by a liveness lapse.

> **Status: the deterministic heart is implemented; there is no release, and
> no daemon.** Of all the modules in this set, this is the one least suited to
> being used before it has been reviewed: a false release cannot be undone.
>
> **In, and tested:** the domain (seals, custodians, M-of-N thresholds,
> release conditions, ceremony records, the attempt trail's event shape);
> threshold split and **verified** reconstruction; the liveness state machine
> as a pure function; `SealStore` with an in-memory and a Postgres adapter
> behind one conformance suite; the `Notifier` port; the attempt trail,
> recorded through [`audit`](https://github.com/laenenai/audit).
>
> **Deliberately out of scope in this pass**, each noted here rather than left
> to be discovered:
>
> - **Real notification channels.** `Notifier` is a port with no adapters, and
>   therefore with no conformance suite yet — a suite whose only
>   implementation is a test double written in the same commit tests the
>   double. The suite lands with the first real channel, because the adapter
>   is what determines what the suite can honestly demand.
> - **A running daemon or scheduler loop.** `EvaluateLiveness` is a pure
>   function of `(schedule, proofs-of-life, now)`; nothing here calls it on a
>   tick, sends a notification, or releases a share. Deriving the state rather
>   than storing it is what makes that daemon crash-safe when it arrives, so
>   the order is deliberate.
> - **The custodian ceremony documentation.** The charter's fifth safety
>   property — "the ceremony must be executable by someone who cannot ask the
>   author" — makes the procedure a deliverable, and it is **the next pass**.
>   Until it exists, this module's fifth property is unmet: the mechanism
>   works and the instructions a custodian would need do not exist.

## Why it exists

Access control is enforced by whoever administers access control. No policy
engine can promise that no future rule will grant access, because rules are
mutable and administrators exist.

So for the cases where "private under all circumstances" has to survive the
administrator, the operator, a subpoena and every future policy change, the
only mechanism left is one where **the system cannot decrypt**. This module is
that key's custody mechanism.

As of 2026-10-23 there are **two** enforcement tiers, not three: discretionary
grants (`iam`, default-deny, everything revocable) and cryptographic custody
(here). The mandatory middle tier — classifications no grant could satisfy — is
removed, because a classification is itself a deny administered by policy and
so inherited the weakness in the paragraph above; **there is no deny mechanism
at all, by intent.** "This principal may never see this" is expressed by never
granting it, and an absolute is a key the deployment does not hold. See
[`CHARTER.md`](CHARTER.md) for the full argument and what it cost.

So the consequence, stated rather than left to be discovered: **policy makes no
absolute promises**, and everything absolute is here — where the cost is total.
A crypto-sealed document cannot be indexed, extracted, summarised or searched.
You cannot ask the brain what your own will says.

## Five safety properties

The design is driven by the failure rather than the feature, because releasing
a sealed thing early cannot be undone:

1. **The system holds at most one share and is never sufficient.** N−1 shares
   live outside the deployment — so it can neither unseal alone, nor lose the
   sealed thing if it dies.
2. **A liveness lapse releases a share, not the content.** A dead-man's switch
   that unseals is one that eventually misfires; one that contributes a single
   share still requires a named human custodian to act.
3. **Escalating notification, then a grace period any single proof-of-life
   cancels.** A hospital stay or a lost phone must not release anything.
4. **Re-sealing rotates the key**, so previously distributed shares become
   useless rather than merely superseded.
5. **The ceremony must be executable by someone who cannot ask the author** —
   which makes the procedure documentation a deliverable, not an afterthought.

Each property is enforced by a type or a method rather than by a code path
that has to remember it, and each has a named test:

| Property | Enforced by | Proved by |
|---|---|---|
| 1. at most one share, never sufficient | `Threshold.Validate` (M ≥ 2), `Seal.Validate`, a port with no plural for the held share, `escrow.held_share`'s primary key, a partial unique index on the system custodian | `SystemHoldsAtMostOneShare`, `SystemSharesAreNeverSufficient`, `ConcurrentHoldShareYieldsOneWinner`, `TestASecondHeldShareIsNotARepresentableState` |
| 2. a lapse releases a share, not the content | the effect is a total function of the condition's kind; a `CHECK` constraint says the same in the catalog | `TestLivenessLapseNeverUnseals`, `TestOnlyTheThresholdCanUnseal` |
| 3. escalation over independent channels, then a cancellable grace period | `LivenessSchedule.Validate`; the whole timeline derived from the most recent proof | `TestLivenessPropertiesHoldOnGeneratedTimelines`, `TestAnySingleProofOfLifeCancels` |
| 4. re-seal rotates the key | `Rotate` mints a new key; shares carry their generation; `ReplaceSeal` discards the held share atomically | `TestRotateMakesOldSharesFail`, `ReSealRotatesTheKeyAndDiscardsTheHeldShare` |
| 5. a ceremony anyone can execute | — | **not yet: the next pass** |

## Reconstruction is verified, which is the point

Shamir's scheme is not authenticated. A custodian who supplies a corrupted or
fabricated share causes a **wrong key** to be interpolated, silently, with no
error — measured, not assumed. So every seal records a commitment to the key
its generation sealed, and reconstruction returns an error and **no key**
rather than something key-shaped that is not the key.

The implementation choice behind that, and the evidence for it, is in
[`docs/superpowers/spikes/2026-10-23-shamir-library/NOTES.md`](docs/superpowers/spikes/2026-10-23-shamir-library/NOTES.md):
eight candidate libraries evaluated on licence, dependency weight, finite
field, maintenance and *measured* secrecy, with an independent known-answer
vector committed as a permanent test.

## What it does not do

Envelope encryption itself, authorization rules, or any knowledge of what the
sealed thing is.

## Documentation

- [`CHARTER.md`](CHARTER.md)
- [`SECURITY.md`](SECURITY.md)
- [`CONVENTIONS.md`](CONVENTIONS.md)
- `api.txt` — the public surface as a golden file, diffed in CI
- `docs/superpowers/spikes/` — the decisions that needed evidence

## Running the tests

    mise run test       # the inner loop: no containers, no databases
    mise run test-all   # everything, including the Postgres adapter
    mise run check      # the gate: fmt-check, lint, build, test-all

The database-backed tests skip at run time under `-short`, never behind a
build tag, and start a `pgvector/pgvector:pg18` container through
testcontainers-go unless `TEST_DATABASE_URL` is set.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
