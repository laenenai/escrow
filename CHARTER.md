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

## Relationship to the two enforcement tiers

Per `iam` and kgs as of 2026-10-23, authorization has **two** tiers:
**discretionary** — ReBAC grants over a containment hierarchy, default-deny —
and **cryptographic**, a key the deployment does not hold. There is no third,
and there is no deny mechanism at all; that is an anti-goal rather than a
restriction that emerged from an implementation.

The argument this section used to make as one of three now stands alone, which
makes it stronger and not weaker. Policy is enforced by whoever administers
policy, so a deny administered by policy is only as absolute as whoever
administers the policy. "This principal may never see this" is therefore
expressed by **never granting it** — and an absolute that must survive a future
administrator, an operator, a subpoena and every future rule change is **a key
the deployment does not hold**. This module is that key's custody mechanism,
and it is now the whole of the system's answer rather than the third of three
options.

**What was removed, and why, because the sentence this section used to end on
named a thing that no longer exists.** The earlier framing had a middle tier —
mandatory classifications that no grant could satisfy, with `iam` recording a
classification's **enforcement class** and `escrow` making the crypto class
real. That tier is gone from `iam`: classifications, clearance groups,
mandatory acts, mandatory channels and the mandatory gate in the decision
procedure are all removed, so there is no enforcement class for this module to
be pointed at by. What seals a thing now is the decision to seal it, not a
label whose class resolves here.

It lost on two grounds. First, structurally: **a classification *is* a deny**,
and a deny administered by policy is only as absolute as its administrator — so
the middle tier was promising an absoluteness it could not hold, while routing
ordinary privacy through it turned every preference into an absolute no owner
could lift. Second, by measurement: it made classification *assignment*
cardinality the system's real performance problem. The tier-2 anti-join walked
200,394 rows and turned a 0.46 ms keyset page into **296 ms**, against a tier-1
closure join of 0.006 ms per candidate row, index-served. The diagnosis is the
part worth keeping, because it generalises: that design anchored on "this
principal may never see this" — a rare case — and made it the template for the
common one.

**The consequence has to be stated rather than softened: policy now makes no
absolute promises.** Everything the discretionary tier enforces is grantable,
revocable and administrable by someone. Anything that must be absolute arrives
here instead — and the cost here is total, which means the absolute is also
unreadable. A crypto-sealed document cannot be OCR'd, extracted, indexed,
embedded or summarised. You cannot ask the brain what your own will says. That
cost used to be one option's price among three; it is now the price of
absoluteness in this system, and a user who needs an absolute pays it.

## Adoption

| Consumer | State |
|---|---|
| cas | pending — sealed documents, vault-mode keys, legal hold interaction |
| kgs | pending — per-episode and per-attribute sealing inside an otherwise working graph |
| acre | not expected |

## Provenance

Raised 2026-10-23 from a requirement of the form: *a will must stay private
under every rule the system will ever have, and become readable only on the
author's death, when a named lawyer supplies a key.* That example established
two things — that policy alone cannot make an absolute promise, because policy
is enforced by whoever administers it, and that a third enforcement tier is
therefore required.
Escrowed-with-a-ceremony and a dead-man's switch chosen the same day.

**Half of that finding was superseded later the same day, in this module's
favour.** The middle tier that made this "a third" — mandatory classifications
and clearances — was removed from `iam` on 2026-10-23, because a classification
is itself a deny administered by policy and therefore inherited the very
weakness the first half of this finding identified. The first half is what
won, and it is now load-bearing for the whole system rather than for one tier
of three: policy makes no absolute promises, so an absolute is a key the
deployment does not hold. Kept here as history because the reversal is the
record worth having — only the arithmetic changed, from third of three to
second of two, and from one option among several to the only absolute
mechanism there is.
