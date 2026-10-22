# Charter: `escrow`

**It does this one thing:** Seal a key under M-of-N shares held by named
custodians, and release it only under a recorded ceremony.

Concretely: threshold splitting and reconstruction; custodian records; release
conditions (human act, threshold reached, liveness lapse); the liveness monitor
and its notification schedule; re-seal with key rotation; and an audit trail of
every proof-of-life, notification, share release and unseal attempt — including
the failed ones, which are the interesting signal.

**It must not contain:** Envelope encryption itself (`keyring` — this module
seals *keyring's* KEKs, it does not implement wrapping). Authorization rules
(`iam`). Any domain concept, or any knowledge of what the sealed thing is.

## Why this is its own module

It passes the test that justifies one: a consumer plausibly wants `keyring`
without `escrow` — CAS wants envelope encryption with no threshold custody at
all — but nobody wants `escrow` without `keyring`. One-directional dependency,
two genuinely different jobs.

## Five safety properties, and they are the whole module

This is the one mechanism in the system where a false positive is
**unrecoverable**: releasing a will while its author is alive cannot be undone.
So the design is driven by the failure, not by the feature.

1. **The system holds at most one share and is never sufficient.** N−1 shares
   live outside the deployment. This cuts both ways deliberately: the system
   cannot unseal on its own, *and* the sealed thing is not lost if the
   deployment dies. A design where the service is either necessary or
   sufficient is wrong in both directions.
2. **The liveness lapse releases a share, not the content.** A dead-man's
   switch that unseals is a dead-man's switch that eventually misfires. One
   that contributes one share still requires a named human custodian to act,
   so a false positive costs nothing on its own.
3. **Escalating notification, then a grace period in which any single
   proof-of-life cancels.** A hospital stay, a sabbatical or a lost phone must
   not release anything. Notification runs over multiple independent channels
   before the threshold, and the grace period is cancellable by the principal
   alone.
4. **Re-seal rotates the key.** Cancelling or changing custodians must make
   previously distributed shares useless, which means a new DEK, not reissued
   shares over the old one.
5. **The ceremony must be executable by someone who cannot ask the author.**
   That makes the procedure documentation a deliverable, not an afterthought —
   the custodian needs to know what to do without the one person who is by
   definition unavailable.

## Relationship to the three enforcement tiers

Per the kgs design, authorization has three tiers: discretionary (relation
tuples), mandatory (classifications that no grant can satisfy), and
**cryptographic** — a key the system does not hold. Policy tiers are enforced
by whoever administers policy; only the cryptographic tier survives the
administrator, the operator, a subpoena and every future rule change. This
module is that tier's custody mechanism. `iam` records a classification's
**enforcement class**; `escrow` is what makes the crypto class real.

The cost is total and must be stated to users rather than discovered by them: a
crypto-sealed document cannot be OCR'd, extracted, indexed, embedded or
summarised. You cannot ask the brain what your own will says.

## Adoption

| Consumer | State |
|---|---|
| cas | pending — sealed documents, vault-mode keys, legal hold interaction |
| kgs | pending — per-episode and per-attribute sealing inside an otherwise working graph |
| acre | not expected |

## Provenance

Raised by the owner 2026-10-23, from the requirement: "whatever rule ever
happens my will document should always stay private except if I die and the
lawyer gives the access key" — the example that established that policy alone
cannot make an absolute promise, and that a third enforcement tier is required.
Escrowed-with-a-ceremony and a dead-man's switch chosen the same day.
