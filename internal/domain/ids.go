// This file declares every identifier in the module. All of them are
// structs with a single unexported field, and that shape is the point.
//
// # Why every id is an opaque struct
//
// A named string type (type SealID string) is unforgeable against *mixing* —
// you cannot pass a CustodianID where a SealID is wanted — but it is not
// unforgeable against *construction*: any package can write SealID("x") and
// obtain a value that never went through validation. For most modules that
// is an acceptable trade. It is not acceptable here, for a reason specific
// to this module's charter: the seal id is one of the inputs to the key
// commitment and to every share's binding, so a value that reached a
// commitment without being a canonical id would produce a seal whose shares
// verify against nothing a later process can re-derive.
//
// So the material is unexported and the only ways to obtain an id are the
// mint (NewSealID, NewCeremonyID, NewProofID) and the parse
// (ParseSealID, ParseTenantID, ParseCustodianID, ...). The zero value of
// every id type is the explicit "names nothing" value, reported by IsZero
// and rejected by every Validate.
//
// The cost is stated rather than discovered: an opaque type cannot be a
// map key with a string literal, cannot be built from a database column
// without going through its parser, and must never be given sql.Scanner or
// driver.Valuer — those methods are exported, so any package could then
// construct one from an arbitrary string, which destroys exactly the
// property the type exists for. CONVENTIONS.md records this; the Postgres
// adapter maps each id column to text and converts through the parser at its
// own boundary, one conversion per field.
//
// # Two encodings, because there are two kinds of identifier
//
// Ids this module *mints* (seal, ceremony, proof of life) are 32 lowercase
// hex characters: a 48-bit big-endian millisecond timestamp followed by 80
// bits of cryptographically random entropy. That is a ULID by construction,
// rendered in hex rather than Crockford base32 because this module takes no
// third-party dependency for identity — the same choice audit made, and
// these two modules' ids appear side by side in one audit record, so they
// are spelled the same way. The useful consequence is that lexicographic
// order on the string is chronological order on the mint time.
//
// Ids this module *receives* (tenant, custodian) are opaque to it: a tenant
// id comes from tenancy, a custodian id is a principal id or a bar
// association number or an email address, and which identifier scheme a
// deployment uses is not this module's business. Those are validated for
// shape only — present, bounded, valid UTF-8, no control characters, path
// separators or surrounding whitespace — because such a value becomes a
// database key, a notification address component and an audit-log field, and
// the safe set is the intersection of what all of those accept.

package domain

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// mintedIDBytes is the decoded length of a minted id: 6 timestamp bytes plus
// 10 of entropy.
const mintedIDBytes = 16

// mintedIDTimeBytes is how many of those encode the timestamp — 48 bits of
// milliseconds, which overflows in the year 10889 and is therefore not a
// concern worth a longer field.
const mintedIDTimeBytes = 6

// maxReceivedIDLen bounds a tenant id and a custodian id. Generous relative
// to any real identifier (a ULID is 26 characters) and present to reject a
// deliberately oversized value before it becomes a database key.
const maxReceivedIDLen = 256

// TenantID references the tenant a seal belongs to, opaquely. This module
// stores it, scopes every row by it, and never resolves or interprets it —
// what a tenant is belongs to tenancy, and the value here is whatever that
// module's TenantID rendered to.
//
// It is the column every row-level-security policy in this module's schema
// is keyed on, which is why its shape is validated even though its meaning
// is not: a value that could carry a path separator or a control character
// would reach a policy predicate and a log line as itself.
type TenantID struct{ s string }

// ParseTenantID parses s as a tenant id, validating its shape. See this
// file's doc comment for the rules and why they are the intersection of
// several backends' rather than any one backend's.
func ParseTenantID(s string) (TenantID, error) {
	if err := validateReceivedID("tenant id", s); err != nil {
		return TenantID{}, err
	}
	return TenantID{s: s}, nil
}

// String returns the id unchanged. A tenant id is not a secret.
func (id TenantID) String() string { return id.s }

// IsZero reports whether id names no tenant.
func (id TenantID) IsZero() bool { return id.s == "" }

// SealID identifies one seal globally and permanently. It is minted by this
// module (see NewSealID) and is committed to by the key commitment and by
// every share's binding, so it stays valid when a share is exported, carried
// out of the deployment on paper, and brought back years later.
type SealID struct{ s string }

// NewSealID mints a fresh seal id from clock's current time.
func NewSealID(clock Clock) (SealID, error) {
	s, err := mintID(clock)
	if err != nil {
		return SealID{}, err
	}
	return SealID{s: s}, nil
}

// ParseSealID parses s as a seal id: exactly 32 lowercase hex characters.
// Uppercase is rejected rather than normalized, because the canonical
// spelling is the one the commitment and every distributed share committed
// to — accepting a second spelling would mean two strings that name one seal
// and verify against two different commitments.
func ParseSealID(s string) (SealID, error) {
	if err := validateMintedID("seal id", s); err != nil {
		return SealID{}, err
	}
	return SealID{s: s}, nil
}

// String returns the id as 32 lowercase hex characters.
func (id SealID) String() string { return id.s }

// IsZero reports whether id names no seal.
func (id SealID) IsZero() bool { return id.s == "" }

// CustodianID references one named custodian: the human (or the system)
// who holds one share and whose act is required for a release. It is an
// opaque identifier the caller chooses — a principal id, a professional
// registration number, a mailbox — because the charter puts "any knowledge
// of what the sealed thing is", and of who the people around it are, outside
// this module.
type CustodianID struct{ s string }

// ParseCustodianID parses s as a custodian id, validating its shape.
func ParseCustodianID(s string) (CustodianID, error) {
	if err := validateReceivedID("custodian id", s); err != nil {
		return CustodianID{}, err
	}
	return CustodianID{s: s}, nil
}

// String returns the id unchanged. A custodian id names a person without
// describing anything they hold.
func (id CustodianID) String() string { return id.s }

// IsZero reports whether id names no custodian.
func (id CustodianID) IsZero() bool { return id.s == "" }

// CeremonyID identifies one recorded ceremony: one occasion on which a
// release condition was evaluated and acted on, whether it completed, was
// refused, or failed.
type CeremonyID struct{ s string }

// NewCeremonyID mints a fresh ceremony id from clock's current time.
func NewCeremonyID(clock Clock) (CeremonyID, error) {
	s, err := mintID(clock)
	if err != nil {
		return CeremonyID{}, err
	}
	return CeremonyID{s: s}, nil
}

// ParseCeremonyID parses s as a ceremony id: exactly 32 lowercase hex
// characters.
func ParseCeremonyID(s string) (CeremonyID, error) {
	if err := validateMintedID("ceremony id", s); err != nil {
		return CeremonyID{}, err
	}
	return CeremonyID{s: s}, nil
}

// String returns the id as 32 lowercase hex characters.
func (id CeremonyID) String() string { return id.s }

// IsZero reports whether id names no ceremony.
func (id CeremonyID) IsZero() bool { return id.s == "" }

// ProofID identifies one recorded proof of life. It exists so that the same
// proof arriving twice — a retried webhook, a mail client that opens a link
// twice — is one record rather than two, and so that the attempt trail can
// name the proof it is reporting on.
type ProofID struct{ s string }

// NewProofID mints a fresh proof-of-life id from clock's current time.
func NewProofID(clock Clock) (ProofID, error) {
	s, err := mintID(clock)
	if err != nil {
		return ProofID{}, err
	}
	return ProofID{s: s}, nil
}

// ParseProofID parses s as a proof-of-life id: exactly 32 lowercase hex
// characters.
func ParseProofID(s string) (ProofID, error) {
	if err := validateMintedID("proof id", s); err != nil {
		return ProofID{}, err
	}
	return ProofID{s: s}, nil
}

// String returns the id as 32 lowercase hex characters.
func (id ProofID) String() string { return id.s }

// IsZero reports whether id names no proof of life.
func (id ProofID) IsZero() bool { return id.s == "" }

// ChannelID names one notification channel in the caller's own vocabulary:
// "email", "sms", "postal", "second-contact". It is a named string rather
// than an opaque struct, and that is a deliberate exception to this file's
// rule.
//
// The reason is the one audit gives for Action and Outcome: a channel is a
// vocabulary value, not an identity this module mints or resolves. A caller
// writes one as a literal inside a LivenessSchedule, and a module that
// enumerated the channels a deployment can own would be deciding what the
// channels are — which, for the independence the charter requires, is
// exactly the deployment's decision to make. Nothing is committed to a
// cryptographic input by a channel name, so the construction hazard that
// justifies the opaque ids does not arise.
type ChannelID string

// Validate reports whether c is usable as a channel name: present, bounded,
// and free of the characters that would make it unsafe as a database key or
// a log field. It validates shape, never meaning.
func (c ChannelID) Validate() error {
	return validateReceivedID("channel", string(c))
}

// String returns the channel name unchanged.
func (c ChannelID) String() string { return string(c) }

// mintID returns a fresh 32-character hex identifier: a 48-bit big-endian
// millisecond timestamp from clock, then 80 bits from crypto/rand.
//
// It returns an error rather than panicking when the entropy source fails.
// forbidigo forbids panic outside cmd/, and a library embedded in somebody
// else's process must let that process decide whether to retry, fail the
// request or shut down.
func mintID(clock Clock) (string, error) {
	var raw [mintedIDBytes]byte

	ms := clock.Now().UnixMilli()
	for i := range mintedIDTimeBytes {
		shift := 8 * (mintedIDTimeBytes - 1 - i)
		raw[i] = byte(ms >> shift) //nolint:gosec // deliberate truncation: the low 48 bits are the field
	}

	if _, err := rand.Read(raw[mintedIDTimeBytes:]); err != nil {
		return "", invalidf(ErrMalformedID, "read entropy for an id: %v", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// validateMintedID reports whether s is a canonical minted id: exactly 32
// lowercase hex characters.
func validateMintedID(label, s string) error {
	if len(s) != 2*mintedIDBytes {
		return invalidf(ErrMalformedID, "%s is %d characters, want %d", label, len(s), 2*mintedIDBytes)
	}
	if !isLowerHex(s) {
		return invalidf(ErrMalformedID, "%s is not lowercase hex", label)
	}
	return nil
}

// validateReceivedID reports whether s is safe to use as a database key, a
// policy predicate's right-hand side and a log field: present, bounded,
// valid UTF-8, no control or whitespace characters, no path separators or
// null bytes, and not a relative path element.
//
// The rules are deliberately stricter than any one consumer needs. Widening
// them later is a reviewed change to this one function rather than a
// surprise in one adapter.
func validateReceivedID(label, s string) error {
	switch {
	case s == "":
		return invalidf(ErrMalformedID, "%s is empty", label)
	case len(s) > maxReceivedIDLen:
		return invalidf(ErrMalformedID, "%s is %d bytes, maximum %d", label, len(s), maxReceivedIDLen)
	case !utf8.ValidString(s):
		return invalidf(ErrMalformedID, "%s is not valid UTF-8", label)
	case s == "." || strings.Contains(s, ".."):
		return invalidf(ErrMalformedID, "%s is a relative path element", label)
	case strings.ContainsAny(s, "/\\\x00"):
		return invalidf(ErrMalformedID, "%s contains a path separator or null byte", label)
	case strings.TrimSpace(s) != s:
		return invalidf(ErrMalformedID, "%s has leading or trailing whitespace", label)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return invalidf(ErrMalformedID, "%s contains a control or whitespace character", label)
		}
	}
	return nil
}

// isLowerHex reports whether s consists only of 0-9 and a-f. Uppercase is
// not hex for this module's purposes; see ParseSealID.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return len(s) > 0
}
