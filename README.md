# escrow

Seals a key under M-of-N shares held by named custodians, and releases it only
under a recorded ceremony — by human act, by threshold, or by a liveness lapse
(dead-man's switch).

The system holds at most one share and is never sufficient to unseal; a
liveness lapse releases a share, not the content.

**Not in scope:** envelope encryption itself (`keyring`), authorization rules
(`iam`), any knowledge of what the sealed thing is.

See [CHARTER.md](CHARTER.md) — in particular the five safety properties, since
a false release is unrecoverable.
