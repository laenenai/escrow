// This file holds the two types in the module that carry secret material —
// SealedKey and Share — and the one discipline that applies to both.
//
// # Secret material must not leak through any rendering
//
// Each of them implements **all four** of fmt.Stringer, fmt.Formatter,
// json.Marshaler and slog.LogValuer, every one of them yielding Redacted: a
// fixed placeholder that names the type and says nothing about the value,
// including nothing about its length.
//
// All four are needed, and the reason is mechanical rather than cautious:
//
//   - fmt.Stringer covers %v and %s, and covers a value interpolated into
//     an error with %s.
//   - **%#v ignores Stringer entirely.** fmt's Go-syntax verb reaches for
//     GoStringer and, failing that, walks the struct by reflection and
//     prints the unexported field's bytes. fmt.Formatter is the one
//     interface that intercepts *every* verb, %#v included, which is why it
//     is here rather than GoStringer: GoStringer would fix %#v and leave
//     %x, %q and %b printing material.
//   - **json.Marshal ignores both Stringer and LogValuer.** A secret inside
//     a struct that some handler marshals into a response body is the most
//     consequential of these paths and the one the other three do nothing
//     about.
//   - slog.LogValuer covers slog.Any("share", share) and a share reached as
//     a field of a logged group, which is how a value gets into a log
//     aggregator rather than into one process's stderr.
//
// escrowtest's NoSecretLeaksInAnyRendering asserts all five renderings
// (%v, %s, %+v, %#v and json.Marshal) against the material, its hex and
// base64 encodings, and its length in decimal. The length is in that list
// because "32 bytes" said about a value a caller believes is redacted is
// still information the caller did not choose to publish, and because a
// placeholder that varies with the value is a placeholder that will one day
// vary with the value in a more interesting way.
//
// There is deliberately **no MarshalText and no MarshalBinary** on either
// type. encoding.TextMarshaler is consulted by encoding/json, so a
// MarshalText returning material would reopen the hole MarshalJSON closes;
// and a BinaryMarshaler is exactly the method a generic encoder goes looking
// for. The sanctioned way to get a share's bytes out is Share.Export, whose
// name no interface matches, so no encoder can find it by accident.

package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log/slog"
)

// KeySize is the length in bytes of every key this module seals: 32.
//
// It is fixed rather than a range because of what this module seals. Per
// CHARTER.md it seals keyring's key-encryption keys, which are 32 bytes for
// AES-256, and accepting a shorter key would silently weaken whatever that
// key protects for whoever passed one. A share of a GF(256) Shamir split is
// the same length as the secret, so this is also the length of a share's
// material. A future need for another size is a reviewed change here, not a
// parameter.
const KeySize = 32

// Redacted is the placeholder every rendering of secret material yields. It
// is exported so a consumer's own log scrubbing, and its own tests, can
// assert against the same literal this package writes.
//
// It names the type and nothing else — in particular not the length. See
// this file's doc comment.
const Redacted = "[REDACTED]"

// shareEnvelopeVersion is the leading byte of every exported share. It
// exists so that a format change is detectable in the bytes a custodian
// hands back rather than inferred from a reconstruction that fails for no
// visible reason.
//
// Changing the envelope format requires a new version byte here and a new
// shareChecksumTag below. A share may be on paper in a safe for twenty
// years, so from the first exported share onward the bytes in custody are
// the authority and the code is not.
const shareEnvelopeVersion byte = 0x01

// shareChecksumTag is the domain-separation string mixed into an exported
// share's checksum, following the same construction as the key commitment
// (see CommitKey) and audit's entry digest: the tag's length, the tag, then
// the body. It contains no organisation or module path, because a repository
// rename must not be able to rewrite a cryptographic constant by textual
// substitution — which is a mistake audit made and recorded.
const shareChecksumTag = "escrow:share-envelope:v1"

// shareChecksumLen is how many bytes of the tagged digest an exported share
// carries: 4.
//
// What it is for: detecting a transcription error. A share may be written
// down, read aloud, photographed, or typed back in by a custodian under
// stress, and four bytes turn a mistyped character into ErrInvalidShare
// naming that share instead of an ErrReconstructionUnverified that
// implicates the whole set — which matters directly for the charter's fifth
// property, a ceremony executable by someone who cannot ask the author.
//
// What it is emphatically **not**: authentication. It is unkeyed, so anybody
// who can rewrite a share can recompute it. Only the key commitment can tell
// a fabricated share from a real one, and it does so over the set rather
// than over any one share. A checksum that was mistaken for authentication
// would be worse than none.
const shareChecksumLen = 4

// SealedKey is the key a seal protects: the only secret material this module
// ever lets into a caller's address space, and then only after
// reconstruction has verified it against the seal's commitment.
//
// A SealedKey must be destroyed when the caller is done with it,
// conventionally with defer:
//
//	key, err := escrow.Reconstruct(seal, shares)
//	if err != nil {
//		return err
//	}
//	defer key.Destroy()
//
// Destroy clears the backing array, which every copy of the SealedKey
// shares: copying one is cheap and does not duplicate the secret, so
// destroying it destroys it everywhere rather than only in the variable the
// caller happened to name. The zero SealedKey holds no material and is
// rejected by Validate.
type SealedKey struct {
	// b is the key material. It is unexported, and reachable only through
	// Bytes, so that no struct literal elsewhere can construct a SealedKey
	// that skipped validation, and so that encoding/json cannot reach the
	// material by reflection even without the methods below.
	b []byte
}

// NewSealedKey returns a fresh key read from crypto/rand: the key a seal is
// created around, and the one a re-seal rotates to.
func NewSealedKey() (SealedKey, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return SealedKey{}, invalidf(ErrInvalidKeyMaterial, "read %d bytes of entropy: %v", KeySize, err)
	}
	return SealedKey{b: b}, nil
}

// SealedKeyFrom returns a SealedKey holding a copy of b, or a wrapped
// ErrInvalidKeyMaterial if b is not usable key material.
//
// The copy is deliberate: the caller keeps ownership of its own buffer and
// must zeroize it, and Destroy zeroizes only this copy. It exists so that a
// caller sealing a key it already holds — a keyring KEK, which is the case
// the charter names — does not have to let this module mint it.
func SealedKeyFrom(b []byte) (SealedKey, error) {
	if err := validateKeyMaterial(b); err != nil {
		return SealedKey{}, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return SealedKey{b: out}, nil
}

// Bytes returns the live key material — not a copy, so a caller can hand it
// straight to a cipher without creating a second buffer that also has to be
// zeroized. It returns nil for a destroyed or zero SealedKey. The caller
// must not retain the slice past Destroy and must not modify it.
func (k SealedKey) Bytes() []byte { return k.b }

// Validate reports whether k holds usable key material: present, exactly
// KeySize bytes, and not all-zero.
func (k SealedKey) Validate() error { return validateKeyMaterial(k.b) }

// IsZero reports whether k holds no usable key material, because it is the
// zero value, because it was destroyed, or because its shared backing array
// was zeroized through another copy.
func (k SealedKey) IsZero() bool { return allZero(k.b) }

// Equal reports whether k and other hold the same material, in constant time
// with respect to that material. It exists for tests and for
// reconstruction's own self-check; production code has no reason to compare
// two keys.
func (k SealedKey) Equal(other SealedKey) bool {
	return subtle.ConstantTimeCompare(k.b, other.b) == 1
}

// Destroy zeroizes the key material and leaves k holding none. It is
// idempotent and safe on the zero value. See SealedKey for why it affects
// every copy.
func (k *SealedKey) Destroy() {
	clear(k.b)
	k.b = nil
}

// String returns Redacted. One of the four renderings described in this
// file's doc comment.
func (k SealedKey) String() string { return "SealedKey(" + Redacted + ")" }

// Format implements fmt.Formatter so that **every** verb — %v, %s, %q, %x,
// and %#v, which ignores Stringer — renders the placeholder. See this file's
// doc comment for why Formatter rather than GoStringer.
func (k SealedKey) Format(f fmt.State, verb rune) { writeRedacted(f, verb, k.String()) }

// MarshalJSON returns Redacted as a JSON string, so a SealedKey that ends up
// inside a marshalled struct redacts itself rather than being refused — an
// error here would turn a logging mistake into a failed request — or, far
// worse, encoded.
func (k SealedKey) MarshalJSON() ([]byte, error) { return redactedJSON(), nil }

// LogValue returns Redacted, so slog.Any("key", key) and a slog group
// containing one render the placeholder rather than the key.
func (k SealedKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

// UnmarshalJSON always fails: there is no form of a key on the wire or at
// rest that this module is willing to read back. Accepting one would mean
// accepting plaintext key material from whatever produced the document, when
// the whole point of the module is that the key exists only as shares until
// a ceremony reassembles it.
func (k *SealedKey) UnmarshalJSON([]byte) error {
	return invalidf(ErrInvalidKeyMaterial, "a sealed key cannot be deserialized; reconstruct it from shares")
}

// ShareIndex is a share's x-coordinate: which point on the polynomial this
// share is, 1..MaxShares.
//
// It is **not** an ordinal position. The splitter chooses the x-coordinates,
// and a measured 5-share split produced [227 56 135 108 210] rather than
// 1..5, so nothing here or in Seal.Validate may assume the indices of a
// seal's shares are dense or ordered — only that they are distinct and
// non-zero. See docs/superpowers/spikes/2026-10-23-shamir-library.
//
// Zero is not a valid index and never will be: in Shamir's scheme the
// polynomial's value at zero *is* the secret, so a share at index 0 would be
// the secret itself rather than a share of it.
type ShareIndex uint8

// Validate reports whether i names a real share position.
func (i ShareIndex) Validate() error {
	if i == 0 {
		return invalidf(ErrInvalidShare, "share index 0 is reserved: the polynomial's value at zero is the secret itself")
	}
	return nil
}

// Share is one share of a split key: a point on the polynomial, bound to the
// seal and the generation it was cut under.
//
// The binding is not decoration. A share is distributed to a human and may
// come back years later, after the seal has been re-sealed one or more
// times; the seal id and generation are what let reconstruction reject a
// share from a superseded generation by inspection, before any arithmetic
// (ErrForeignShare). They are not a *guarantee* — the binding is unkeyed and
// a determined holder can rewrite it, which is why the key commitment exists
// and why charter property 4 is tested against a share whose binding has
// been rewritten rather than only against an honest one.
//
// Material is unexported and renders as Redacted through all four
// interfaces; see this file's doc comment. The sanctioned way out is Export.
type Share struct {
	seal       SealID
	generation Generation
	index      ShareIndex
	material   []byte
}

// NewShare returns a Share for the given seal, generation and index, holding
// a copy of material. It is the only constructor, so no Share can exist that
// skipped validation.
func NewShare(seal SealID, generation Generation, index ShareIndex, material []byte) (Share, error) {
	s := Share{seal: seal, generation: generation, index: index}
	if len(material) != 0 {
		s.material = make([]byte, len(material))
		copy(s.material, material)
	}
	if err := s.Validate(); err != nil {
		s.Destroy()
		return Share{}, err
	}
	return s, nil
}

// Seal returns the seal this share was cut from.
func (s Share) Seal() SealID { return s.seal }

// Generation returns the seal generation this share was cut under. A share
// is useless against any other generation — see CHARTER.md's fourth safety
// property and Generation.
func (s Share) Generation() Generation { return s.generation }

// Index returns the share's position in the split.
func (s Share) Index() ShareIndex { return s.index }

// Validate reports whether s is structurally usable: a seal, a real
// generation, a non-zero index, and exactly KeySize bytes of material that
// are not all zero.
//
// All-zero material is rejected for the same reason an all-zero key is: every
// all-zero buffer that actually reaches here is a bug — a destroyed share, or
// a make([]byte, KeySize) nobody filled — and failing closed on it turns "a
// share that interpolates to a predictable point" into an error at the
// boundary.
func (s Share) Validate() error {
	if s.seal.IsZero() {
		return invalidf(ErrInvalidShare, "share names no seal")
	}
	if err := s.generation.Validate(); err != nil {
		return err
	}
	if err := s.index.Validate(); err != nil {
		return err
	}
	switch {
	case len(s.material) == 0:
		return invalidf(ErrInvalidShare, "share %d of seal %s carries no material", s.index, s.seal)
	case len(s.material) != KeySize:
		return invalidf(ErrInvalidShare, "share %d of seal %s carries %d bytes of material, want %d",
			s.index, s.seal, len(s.material), KeySize)
	case allZero(s.material):
		return invalidf(ErrInvalidShare, "share %d of seal %s is all-zero (a destroyed or uninitialized buffer, not a share)",
			s.index, s.seal)
	}
	return nil
}

// IsZero reports whether s holds no material.
func (s Share) IsZero() bool { return allZero(s.material) }

// Destroy zeroizes the share's material and leaves s holding none. As with
// SealedKey.Destroy it affects every copy of the share, because they share
// one backing array.
func (s *Share) Destroy() {
	clear(s.material)
	s.material = nil
}

// Material returns the live share material, for the adapters that must
// persist it and for internal/threshold, which must do arithmetic on it. It
// is not a copy.
//
// It is exported because Go's internal rule is what keeps it unreachable: a
// consumer outside this module cannot name internal/domain, so the only
// published way to a share's bytes is Export, which frames and checksums
// them. The name is deliberately not Bytes, so that a reader of a call site
// inside this module sees that something is reaching for material.
func (s Share) Material() []byte { return s.material }

// Export returns the share as a self-describing byte string, for handing to
// a custodian: a version byte, the length-prefixed seal id, the generation,
// the index, the length-prefixed material, and a four-byte checksum over all
// of it.
//
// The returned bytes **are** the secret — they contain the material — so the
// caller owns the only copy and must handle it as such. The method is called
// Export rather than MarshalBinary or MarshalText precisely so that no
// generic encoder can find it: see this file's doc comment.
//
// Every variable-length field is length-prefixed, which makes the encoding
// injective: a reader can recover the field boundaries from the bytes alone,
// so no two distinct shares share an encoding and a seal id ending in digits
// cannot run into an index.
func (s Share) Export() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	body := make([]byte, 0, 1+8+len(s.seal.s)+4+1+8+len(s.material))
	body = append(body, shareEnvelopeVersion)
	body = appendLenPrefixed(body, []byte(s.seal.s))
	body = binary.BigEndian.AppendUint32(body, uint32(s.generation))
	body = append(body, byte(s.index))
	body = appendLenPrefixed(body, s.material)

	sum := shareChecksum(body)
	return append(body, sum[:shareChecksumLen]...), nil
}

// ImportShare parses a share exported by Share.Export, rejecting a wrong
// version byte, a truncated envelope, a failed checksum, and any share that
// does not then pass Validate.
//
// A failed checksum is reported as ErrInvalidShare naming the index, which
// is the whole reason the checksum is there: a custodian who mistyped one
// character learns that it was their share, rather than everyone learning
// that the set did not reconstruct. It is not authentication — see
// shareChecksumLen.
func ImportShare(b []byte) (Share, error) {
	const minEnvelope = 1 + 8 + 4 + 1 + 8 + shareChecksumLen
	if len(b) < minEnvelope {
		return Share{}, invalidf(ErrInvalidShare, "exported share is %d bytes, too short to be an envelope", len(b))
	}
	if b[0] != shareEnvelopeVersion {
		return Share{}, invalidf(ErrInvalidShare, "exported share has envelope version %#x, want %#x", b[0], shareEnvelopeVersion)
	}

	body, carried := b[:len(b)-shareChecksumLen], b[len(b)-shareChecksumLen:]
	sum := shareChecksum(body)
	if subtle.ConstantTimeCompare(carried, sum[:shareChecksumLen]) != 1 {
		return Share{}, invalidf(ErrInvalidShare, "exported share failed its checksum: it was altered or mistranscribed")
	}

	rest := body[1:]
	sealBytes, rest, ok := takeLenPrefixed(rest)
	if !ok {
		return Share{}, invalidf(ErrInvalidShare, "exported share has a malformed seal id field")
	}
	seal, err := ParseSealID(string(sealBytes))
	if err != nil {
		return Share{}, err
	}
	if len(rest) < 5 {
		return Share{}, invalidf(ErrInvalidShare, "exported share is truncated after its seal id")
	}
	generation := Generation(binary.BigEndian.Uint32(rest[:4]))
	index := ShareIndex(rest[4])
	material, rest, ok := takeLenPrefixed(rest[5:])
	if !ok || len(rest) != 0 {
		return Share{}, invalidf(ErrInvalidShare, "exported share has a malformed material field")
	}

	return NewShare(seal, generation, index, material)
}

// String returns Redacted together with the share's binding, which is not
// secret: the seal, the generation and the index are exactly the fields an
// operator needs in a log line to tell one share apart from another, and
// none of them says anything about the material.
func (s Share) String() string {
	return fmt.Sprintf("Share(seal=%s gen=%s index=%d material=%s)", s.seal, s.generation, s.index, Redacted)
}

// Format implements fmt.Formatter so that every verb, %#v included, renders
// String's output rather than the struct.
func (s Share) Format(f fmt.State, verb rune) { writeRedacted(f, verb, s.String()) }

// MarshalJSON renders the binding as an object and the material as Redacted.
// json.Marshal consults neither Stringer nor LogValuer, so without this
// method a share inside a marshalled struct would be encoded — see this
// file's doc comment.
func (s Share) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `{"seal":%q,"generation":%d,"index":%d,"material":%q}`,
		s.seal.s, uint32(s.generation), s.index, Redacted), nil
}

// LogValue renders the binding as a slog group with the material redacted, so
// an adapter can log a share structurally without reaching for its fields.
func (s Share) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("seal", s.seal.s),
		slog.Uint64("generation", uint64(s.generation)),
		slog.Uint64("index", uint64(s.index)),
		slog.String("material", Redacted),
	)
}

// UnmarshalJSON always fails: the JSON form of a share is redacted, so
// reading one back would produce a share with no material that would then
// fail to reconstruct for a reason the caller could not see. ImportShare is
// the way back in.
func (s *Share) UnmarshalJSON([]byte) error {
	return invalidf(ErrInvalidShare, "a share cannot be deserialized from JSON; use ImportShare on its exported form")
}

// shareChecksum returns the tagged digest of an exported share's body,
// following the same construction as CommitKey: the tag's length, the tag,
// then the body. Truncated to shareChecksumLen by the caller.
func shareChecksum(body []byte) [sha256.Size]byte {
	h := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(shareChecksumTag)))
	h.Write(length[:])
	h.Write([]byte(shareChecksumTag))
	h.Write(body)

	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// writeRedacted is the single implementation behind both Format methods: it
// writes the placeholder for every verb, deliberately ignoring the verb and
// any width or precision flags.
//
// Ignoring them is the point. A %.8s that honoured its precision would print
// eight characters of something, and the whole contract of these types is
// that no verb and no flag combination produces anything but the
// placeholder. The error from fmt.State.Write is discarded because there is
// nothing a Format method can do with it and returning it is not in the
// interface.
func writeRedacted(f fmt.State, _ rune, text string) {
	_, _ = f.Write([]byte(text))
}

// redactedJSON returns Redacted as a JSON string. One function so the quoting
// cannot drift between the two MarshalJSON implementations.
func redactedJSON() []byte { return []byte(`"` + Redacted + `"`) }

// validateKeyMaterial is the one definition of "usable key material" this
// package has: present, exactly KeySize bytes, not all-zero. See
// SealedKey.Validate for why all-zero is an error rather than an
// astronomically unlikely random key.
func validateKeyMaterial(b []byte) error {
	switch {
	case len(b) == 0:
		return invalidf(ErrInvalidKeyMaterial, "empty")
	case len(b) != KeySize:
		return invalidf(ErrInvalidKeyMaterial, "%d bytes, want %d", len(b), KeySize)
	case allZero(b):
		return invalidf(ErrInvalidKeyMaterial, "all-zero (a destroyed or uninitialized buffer, not a key)")
	}
	return nil
}

// allZero reports whether b is empty or every byte of it is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// appendLenPrefixed appends an 8-byte big-endian length followed by b. Eight
// bytes is more than any field here needs and is used for every field so
// that the framing is uniform.
func appendLenPrefixed(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len(b)))
	return append(dst, b...)
}

// takeLenPrefixed reads one length-prefixed field from the front of b,
// returning the field, the remainder, and whether the framing was
// well-formed. A length that overruns the buffer is not well-formed, which is
// the check that keeps a crafted envelope from causing a panic in a library
// embedded in somebody else's process.
func takeLenPrefixed(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 8 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint64(b[:8])
	// len(b) >= 8 is established by the branch above, so the subtraction
	// cannot go negative and the conversion cannot wrap.
	if n > uint64(len(b)-8) { //nolint:gosec // len(b) >= 8, checked immediately above
		return nil, nil, false
	}
	return b[8 : 8+n], b[8+n:], true
}
