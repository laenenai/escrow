# Spike: which Shamir implementation does `escrow` depend on?

**Date:** 2026-10-23
**Question:** `escrow` needs an M-of-N threshold split. Hand-rolling GF(256)
arithmetic for the module whose charter says a false release is
*unrecoverable* is the wrong default, so: which published Go implementation
does it import, and on what evidence?
**Answer:** `github.com/mvrahden/go-shamir v0.3.0`.
**Measurements below were executed, not read off a README.**

## Criteria, in the order they decided it

1. License compatible with being imported by an Apache-2.0 **public** library.
2. Importable as an ordinary library — `escrow` vendors nothing.
3. cgo-free (`CGO_ENABLED=0` is a release constraint for every module here).
4. Correct: GF(256) over the Rijndael polynomial, and **information-theoretic
   secrecy actually preserved**.
5. An API that returns plain bytes, so share material can be wrapped in a
   type that does not render (`domain.Share`).
6. Dependency weight, which for a published library is pushed onto every
   consumer's SBOM and vulnerability scanner.
7. Maintenance state.

## The candidates

| | hashicorp/vault/shamir | openbao sdk/v2 | **mvrahden/go-shamir** | corvus-ch/shamir | lafriks/go-shamir | codahale/sss | dsprenkels/sss-go | cloudflare/circl |
|---|---|---|---|---|---|---|---|---|
| Latest | v1.21.4 2026-03-05 | v2.7.1 2026-09-23 | **v0.3.0 2026-08-10** | v1.0.1 2022-08-23 | v1.2.1 2026-07-15 | 2016 (archived) | v0.1.2 2019 | v1.6.5 2026-08-05 |
| License | MPL-2.0 in-dir, **BUSL-1.1 at the module root** | MPL-2.0 | **MPL-2.0** | MPL-2.0 | MIT | MIT | MIT | BSD-3 |
| cgo | no | no | **no** | no | no | no | **yes** | no |
| Modules in build list | **545** | **96** | **5** (library is stdlib-only) | 2 | 2 | n/a | n/a | 5 |
| Field | 0x11B | 0x11B | **0x11B** | **0x11D** | 0x11B | 0x11B | — | prime scalar field |
| Perfect secrecy | yes | yes | **yes (measured)** | yes | **no (measured)** | **no** | — | yes |
| Verdict | rejected | runner-up | **chosen** | rejected | rejected | rejected | rejected | wrong primitive |

### Why each rejection

- **`hashicorp/vault/shamir`** — the `shamir/` directory does carry its own
  MPL-2.0 `LICENSE`, so it is legally importable. It is still not usable
  here. The module root is BUSL-1.1, which is what a license scanner reads
  first; the module drags 545 modules into the build list; and
  `govulncheck` against a toy module that imports nothing but
  `vault/shamir` reports **four advisories with "Fixed in: N/A"**, attributed
  to the `shamir.Split` call because Vault's advisories carry no
  affected-symbol data. Every consumer of `escrow` would inherit four
  permanently red, unfixable findings. For a public library that is
  disqualifying on its own.
- **`corvus-ch/shamir`** — MPL-2.0, zero dependencies, perfect secrecy
  intact, and the only streaming (`io.Reader`/`io.Writer`) API in the field.
  Rejected for one reason: its log table resolves to **GF(2⁸) mod 0x11D**,
  not Rijndael's 0x11B. That is deliberate — it targets `libgfshare`
  compatibility — but it isolates the implementation: it cannot be validated
  against the TSS vector below (it returns `7667737602` where the vector says
  `7465737400`), it is not SLIP-0039-compatible, and its one
  cross-implementation reference, `digital-scurf.org/software/libgfshare`,
  now 404s. An escrow module that cannot check its own arithmetic against
  anything outside itself is the situation this spike exists to avoid.
- **`lafriks/go-shamir`** — painful rejection. MIT (no copyleft at all), zero
  dependencies, the cleanest code of the lot, `crypto/rand` throughout with
  no global state, recent releases, and bit-for-bit wire compatibility with
  Vault. It is rejected **only** because
  `generateCoefficients` forces the leading coefficient non-zero ("or else
  it's a lower degree polynomial"), which forfeits information-theoretic
  secrecy: with exactly k−1 shares one candidate value per secret byte can be
  excluded. Measured — 1-byte secret, k=2, n=255, 200 000 trials, counting
  `y == secret` at x=1 — it scores **0** where uniformity predicts ~781. The
  leak is tiny (~0.18 bits over a 32-byte key) and for most libraries it
  would be a footnote. For the module whose entire proposition is "k−1 shares
  reveal *nothing*", shipping a scheme that gives up the theorem is the wrong
  trade. If upstream dropped the constraint this would be the obvious first
  choice.
- **`codahale/sss`** — archived 2016-05-01, no `go.mod`, `Combine` has no
  error return at all, non-constant-time `mul`/`div`, and the same
  leading-coefficient flaw as above.
- **`dsprenkels/sss-go`** — `import "C"`. Disqualified by `CGO_ENABLED=0`.
- **`cloudflare/circl/secretsharing`** — real and well maintained, but it is
  Shamir over the **scalar field of a prime-order group**, not GF(256): the
  secret must fit in one scalar and a share is a group element rather than
  bytes. Its own documentation warns that recovery is not constant time on
  the NIST curves. Worth revisiting only if `escrow` ever wants *verifiable*
  secret sharing (CIRCL also ships Feldman VSS), which would be a different
  construction and a charter conversation.
- **Checked and non-existent:** `hashicorp/go-sss`, `superwhiskers/shamir`,
  `filippo.io/shamir`. **Checked and has no secret sharing at all:**
  `tink-go` (the upstream `google/tink` is archived; a code search across
  `org:tink-crypto` for `shamir`/`secretsharing` returns nothing).
  **Checked and rejected on provenance:** `sensify-security/shamir` (no git
  tags, and its README misstates its own license as Apache-2.0 when the code
  is MPL-2.0 — license confusion in a crypto dependency is disqualifying),
  `fadhilkurnia/shamir` (no LICENSE file).
  **Checked and no raw-share API:** `shurlinet/go-slip39` exports only
  SLIP-0039 mnemonic-level split/combine; its `gf256.go` exports nothing.

### The close call: `openbao/openbao/sdk/v2/helper/shamir`

This was the runner-up and the decision between the two is the only genuinely
arguable part of this spike. (Note the path: it is `sdk/helper/shamir`, not
`openbao/shamir` — OpenBao moved it into the public SDK in 2024.)

**For it:** unambiguous MPL-2.0 with no BUSL anywhere in the module;
institutionally maintained (Linux Foundation project, the designated MPL-2.0
continuation of exactly this code lineage); and it is the one candidate whose
RNG is *better* than Vault's — it removed `math/rand` entirely in favour of a
`crypto/rand.Int`-driven Fisher–Yates shuffle for the x-coordinates.

**Against it, and decisively:** OpenBao put those 250 stdlib-only lines in its
**monolithic `sdk/v2` module**, which requires gRPC, the docker/moby client
and API, pgx, OpenTelemetry, cel-go and go-jose — **96 modules in the build
list for one `Split` call.** Go's graph pruning means nothing extra compiles
and `go.sum` stays tiny, but `go list -m all`, `go mod graph`, SBOM
generators, Dependabot and Snyk all walk the unpruned graph, and
`govulncheck` already reports 13 advisories in required-but-uncalled modules.
`escrow` is published public and sits under `keyring`, `cas` and `kgs`, so
that graph is pushed onto all of them permanently. It is also precisely the
"platform catch-all" shape this set of modules exists to refuse.

The tiebreaker is asymmetry of what `escrow` can fix itself:

- The risk of the lighter dependency is **maintenance** — one author, v0.x,
  41 stars, frozen at a snapshot of Vault v1.17.3. That risk is almost
  entirely neutralised *inside this repository*, by the tests listed below:
  if an upgrade changes the field, the share layout, or the coefficient
  distribution, `escrow`'s own CI fails. The arithmetic in question has not
  changed algorithmically in a decade.
- The risk of the heavier dependency is a **96-module graph for every
  downstream consumer**, which `escrow` cannot mitigate at all, plus a second
  reorganisation of `sdk/v2` (shamir has already moved once).

So: the light dependency, with the maintenance risk converted into tests.
Because `mvrahden`, `openbao` and `hashicorp/vault` are all bit-for-bit
wire-compatible and all pass the known-answer vector below, **swapping to
OpenBao later is a one-line change that the same tests validate** — which is
the property that makes this reversible and therefore the right call now.

## What was measured, and how

Executed against `mvrahden/go-shamir v0.3.0` with Go 1.25.6.

**1. An independent known-answer vector.**
`draft-mcgrew-tss-03` §9 ("Test Cases"),
<https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03>, specifies
Threshold Secret Sharing over GF(256) using "the unique irreducible
polynomial with minimum weight of degree 8" — 0x11B, the AES polynomial — and
publishes:

```
secret = 7465737400          ("test\0"),  M = 2, N = 2
share 1 = B9FA07E185
share 2 = F5409B4511
```

Encoding each share as `value || index`, which is this library's layout:

```
TSS vector: got=7465737400 match=true
```

The vector pins **both** the field and the share layout, which is why it is
worth more than a round-trip test. It is an expired individual IETF
submission and never became an RFC — that is its one weakness — but it is the
only published raw-GF(256)-Shamir known-answer test that exists, and Botan's
TSS, `tss-rb` and OASIS SAM-TSS v1.0 all validate against it. It is committed
as a permanent test: `TestTSSKnownAnswerVector`.

SLIP-0039's 45 official vectors
(<https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json>)
exercise the same field but only transitively, through PBKDF2, a Feistel
construction, a digest share and an RS1024 checksum. They cannot be fed to a
bare `Split`/`Combine`, so they are noted and not used.

Vault's own `shamir_test.go` fixtures were examined and are **not** usable as
field evidence: its hardcoded `mult(3,7)==9` holds for *any* degree-8
irreducible polynomial, because `(x+1)(x²+x+1) = x³+1` needs no reduction.

**2. Information-theoretic secrecy.** 1-byte secret `0x42`, k=2, n=255,
200 000 splits, counting how often the share at x=1 equals the secret.
Uniformity predicts samples/256 ≈ 781:

```
run 1: samples=200000 hits=815  expected=781.2
run 2: samples=200000 hits=786  expected=781.2
```

Within noise. The same measurement scores exactly 0 against
`lafriks/go-shamir`, which is how that flaw was found rather than assumed.
Committed as `TestSharesAreUniformlyDistributed`.

**3. The malleability this module has to defend against.** Both of these
return a **wrong key and a nil error**:

```
combine(2 of 5)        err=<nil> match=false   // below threshold
corrupted share        err=<nil> match=false   // one byte flipped
```

That is not a defect in the library — it is Shamir's scheme, which is not
authenticated — and it is the entire justification for
`domain.KeyCommitment` and `domain.ErrReconstructionUnverified`. Had the
library returned an error here, the commitment would still be required,
because a *fabricated* share is indistinguishable from a real one by
construction.

**4. Share shape and x-coordinates.**

```
split(32-byte key, n=5, k=3): len(part)=33, x in the trailing byte
x coords run 1=[227 56 135 108 210]
x coords run 2=[40 30 167 27 49]
```

Two consequences for `escrow`'s own design, both acted on:

- A share is `len(secret)+1` bytes with the x-coordinate last, so
  `internal/threshold` splits it into `domain.Share`'s material and index at
  the boundary and `domain.KeySize` stays the material length.
- **The x-coordinates are chosen by the splitter and are not `1..N`.** So
  `domain.ShareIndex` is documented as the polynomial's x-coordinate rather
  than an ordinal, and `domain.Seal.Validate` requires the custodians'
  indices to be *distinct and non-zero* rather than to cover `1..Total`. An
  earlier draft required `1..Total` and would have rejected every real split.

**5. Error hygiene.** No error string from the library reproduces material:

```
"cannot split an empty secret"
"parts cannot be less than threshold"
"less than two parts cannot be used to reconstruct the secret"
"duplicate part detected"
```

So `escrow` can wrap these without a scrubbing step. `Split` and `Combine`
take and return plain `[][]byte` and define no `String`, `Format`,
`MarshalJSON` or `LogValue`, which is what lets `domain.Share` own the
rendering discipline entirely.

## What this spike does **not** settle

- **Hand-rolling.** It was not needed, so the fallback — a hand-rolled
  GF(256) implementation validated against the TSS vector — was not built.
  The vector is committed anyway, which means a future decision to hand-roll
  starts with its acceptance test already in the repository.
- **Verifiable secret sharing.** Nothing here lets a custodian prove their
  share is genuine *before* a ceremony; the commitment verifies the
  reconstructed key, which localizes a bad share to "someone in this set".
  Feldman or Pedersen VSS would localize it to a custodian, at the cost of a
  prime-order group and a charter conversation about what `escrow` is. Noted
  as a possible future increment, not a gap in this one.
- **Share refresh.** Proactive secret sharing (re-randomising shares without
  changing the key) is a different mechanism from re-sealing, and the charter
  asks for re-sealing.
