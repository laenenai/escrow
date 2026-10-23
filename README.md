# escrow

[![ci](https://github.com/laenenai/escrow/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/escrow/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/escrow.svg)](https://pkg.go.dev/github.com/laenenai/escrow)

Seals a key under M-of-N shares held by named custodians, and releases it only
under a recorded ceremony — by human act, by threshold, or by a liveness lapse.

> **Status: design only.** This repository currently contains the charter and
> the boundary. There is no implementation yet, and no release. Of all the
> modules in this set, this is the one least suited to being used before it has
> been reviewed: a false release cannot be undone.

## Why it exists

Access control is enforced by whoever administers access control. No policy
engine can promise that no future rule will grant access, because rules are
mutable and administrators exist.

So for the cases where "private under all circumstances" has to survive the
administrator, the operator, a subpoena and every future policy change, the
only mechanism left is one where **the system cannot decrypt**. This module is
that tier's custody mechanism.

The cost is total and must be stated to users rather than discovered by them: a
crypto-sealed document cannot be indexed, extracted, summarised or searched.

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

## What it does not do

Envelope encryption itself, authorization rules, or any knowledge of what the
sealed thing is.

## Documentation

- [`CHARTER.md`](CHARTER.md)
- [`SECURITY.md`](SECURITY.md)
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
