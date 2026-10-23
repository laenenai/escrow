package domain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// renderingSealID is the seal id the rendering tests use. It is all 'a'
// deliberately: a minted id is 32 random hex characters, and a random one
// would sometimes contain the substring "32" — which is KeySize in decimal,
// the value the leak assertions must be able to search for. A fixed id with
// no digits at all makes the length assertion mean what it says.
const renderingSealID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// renderingIndex is likewise chosen so that no part of a share's public
// binding renders as KeySize in decimal.
const renderingIndex ShareIndex = 7

// TestSecretMaterialRendering is the test for the convention stated in
// secret.go's doc comment: a type holding key material or share bytes
// implements all four of fmt.Stringer, fmt.Formatter, json.Marshaler and
// slog.LogValuer, and none of the five renderings a value can reach
// (%v, %s, %+v, %#v, json.Marshal) contains the material.
func TestSecretMaterialRendering(t *testing.T) {
	t.Parallel()

	key, share := renderingFixtures(t)
	material := bytes.Clone(share.Material())
	keyBytes := bytes.Clone(key.Bytes())

	// NoSecretLeaksInAnyRendering is the named subtest the convention
	// requires. It asserts the negative — that no rendering contains the
	// material, any encoding of it, or its length in decimal — across the
	// value itself, a pointer to it, and a struct that merely contains it,
	// which is how a secret actually escapes in practice.
	t.Run("NoSecretLeaksInAnyRendering", func(t *testing.T) {
		t.Parallel()

		type carrier struct {
			Label string
			Key   SealedKey
			Share Share
		}
		holder := carrier{Label: "a struct somebody logged", Key: key, Share: share}

		subjects := map[string]any{
			"SealedKey":              key,
			"*SealedKey":             &key,
			"Share":                  share,
			"*Share":                 &share,
			"a struct containing it": holder,
			"a pointer to that":      &holder,
			"a slice of shares":      []Share{share, share},
			"a map of shares":        map[string]Share{"one": share},
		}

		for name, subject := range subjects {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				renderings := map[string]string{
					"%v":  fmt.Sprintf("%v", subject),
					"%s":  fmt.Sprintf("%s", subject),
					"%+v": fmt.Sprintf("%+v", subject),
					"%#v": fmt.Sprintf("%#v", subject),
					// %q and %x are not in the convention's list of five, but
					// they are exactly the verbs a Stringer-only type leaks
					// through, so a Formatter is asserted against them too.
					"%q": fmt.Sprintf("%q", subject),
					"%x": fmt.Sprintf("%x", subject),
				}
				encoded, err := json.Marshal(subject)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				renderings["json.Marshal"] = string(encoded)

				for verb, text := range renderings {
					assertNoMaterial(t, verb, text, keyBytes, material)
					if !strings.Contains(text, Redacted) {
						t.Fatalf("%s rendered as %q, which does not contain the %s placeholder: "+
							"a rendering that says nothing about the value must still say that it is redacting one",
							verb, text, Redacted)
					}
				}
			})
		}
	})

	// The exact renderings, asserted by equality rather than by absence.
	// Equality is the stronger form: it rules out the material, every
	// encoding of it and its length at once, and it fails if a future change
	// starts appending something nobody reviewed.
	t.Run("the renderings are exactly the placeholder", func(t *testing.T) {
		t.Parallel()

		wantKey := "SealedKey(" + Redacted + ")"
		for verb, got := range map[string]string{
			"%v":  fmt.Sprintf("%v", key),
			"%s":  fmt.Sprintf("%s", key),
			"%+v": fmt.Sprintf("%+v", key),
			"%#v": fmt.Sprintf("%#v", key),
			"%q":  fmt.Sprintf("%q", key),
			"%x":  fmt.Sprintf("%x", key),
		} {
			if got != wantKey {
				t.Fatalf("SealedKey %s = %q, want %q", verb, got, wantKey)
			}
		}
		if got := key.String(); got != wantKey {
			t.Fatalf("SealedKey.String() = %q, want %q", got, wantKey)
		}
		if got, err := json.Marshal(key); err != nil || string(got) != `"`+Redacted+`"` {
			t.Fatalf("json.Marshal(SealedKey) = %s, %v", got, err)
		}
		if got := key.LogValue().String(); got != wantKey {
			t.Fatalf("SealedKey.LogValue() = %q, want %q", got, wantKey)
		}

		// A share's binding is not secret and is rendered on purpose: the
		// seal, the generation and the index are what let an operator tell
		// one share from another in a log line.
		wantShare := "Share(seal=" + renderingSealID + " gen=g1 index=7 material=" + Redacted + ")"
		for verb, got := range map[string]string{
			"%v":  fmt.Sprintf("%v", share),
			"%s":  fmt.Sprintf("%s", share),
			"%+v": fmt.Sprintf("%+v", share),
			"%#v": fmt.Sprintf("%#v", share),
		} {
			if got != wantShare {
				t.Fatalf("Share %s = %q, want %q", verb, got, wantShare)
			}
		}
		wantJSON := `{"seal":"` + renderingSealID + `","generation":1,"index":7,"material":"` + Redacted + `"}`
		got, err := json.Marshal(share)
		if err != nil || string(got) != wantJSON {
			t.Fatalf("json.Marshal(Share) = %s, %v, want %s", got, err, wantJSON)
		}
	})

	// The zero value and a destroyed value must render the same way. A
	// placeholder that varied with the state would tell a reader whether a
	// secret was present, which is information the caller did not publish.
	t.Run("a zero or destroyed value renders identically", func(t *testing.T) {
		t.Parallel()

		live, dead := renderingFixtures(t)
		dead.Destroy()
		liveCopy := live
		liveCopy.Destroy()

		for label, pair := range map[string][2]string{
			"SealedKey": {fmt.Sprintf("%#v", live), fmt.Sprintf("%#v", SealedKey{})},
			"Share":     {fmt.Sprintf("%#v", dead), fmt.Sprintf("%#v", Share{})},
		} {
			if label == "Share" {
				// A destroyed share keeps its binding, which is not secret,
				// so it does not render like the zero share. What must hold
				// is that neither reveals material, which the subtest above
				// asserts, and that the placeholder is present.
				if !strings.Contains(pair[0], Redacted) {
					t.Fatalf("a destroyed Share rendered as %q", pair[0])
				}
				continue
			}
			if pair[0] != pair[1] {
				t.Fatalf("a live %s renders as %q and a zero one as %q: the placeholder varies with the value",
					label, pair[0], pair[1])
			}
		}
	})

	// Deserializing either type is refused rather than silently producing an
	// empty one. A SealedKey read back from JSON would be a key somebody
	// transported in plaintext; a Share read back from its redacted JSON
	// would carry no material and fail to reconstruct for a reason the
	// caller could not see.
	t.Run("neither type can be deserialized", func(t *testing.T) {
		t.Parallel()

		var k SealedKey
		if err := json.Unmarshal([]byte(`"anything"`), &k); !errors.Is(err, ErrInvalidKeyMaterial) {
			t.Fatalf("json.Unmarshal into a SealedKey error = %v, want ErrInvalidKeyMaterial", err)
		}
		var s Share
		if err := json.Unmarshal([]byte(`{}`), &s); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("json.Unmarshal into a Share error = %v, want ErrInvalidShare", err)
		}
	})
}

// TestDestroyZeroizesEveryCopy is the behaviour the package doc claims: there
// is one secret, and destroying it destroys it everywhere, not only in the
// variable the caller happened to name.
func TestDestroyZeroizesEveryCopy(t *testing.T) {
	t.Parallel()

	key, err := NewSealedKey()
	if err != nil {
		t.Fatalf("NewSealedKey: %v", err)
	}
	copyOfKey := key
	alias := key.Bytes()

	key.Destroy()

	if !copyOfKey.IsZero() {
		t.Fatal("destroying a key left a copy of it holding material")
	}
	if !allZero(alias) {
		t.Fatal("destroying a key left the backing array non-zero")
	}
	if err := copyOfKey.Validate(); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("a destroyed key validates: %v", err)
	}

	key.Destroy() // idempotent
	var zero SealedKey
	zero.Destroy() // safe on the zero value
}

// TestShareExportRoundTrip covers the form a custodian actually holds.
func TestShareExportRoundTrip(t *testing.T) {
	t.Parallel()

	_, share := renderingFixtures(t)

	exported, err := share.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	back, err := ImportShare(exported)
	if err != nil {
		t.Fatalf("ImportShare: %v", err)
	}
	if back.Seal() != share.Seal() || back.Generation() != share.Generation() || back.Index() != share.Index() {
		t.Fatalf("the binding did not round-trip: got %v", back)
	}
	if !bytes.Equal(back.Material(), share.Material()) {
		t.Fatal("the material did not round-trip")
	}

	// The imported share must not alias the exported bytes, or a caller that
	// zeroized the envelope it was handed would zeroize the share too.
	clear(exported)
	if back.IsZero() {
		t.Fatal("ImportShare aliased the envelope rather than copying it")
	}
}

func TestImportShareRefusesADamagedEnvelope(t *testing.T) {
	t.Parallel()

	_, share := renderingFixtures(t)
	good, err := share.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	tests := map[string]func(b []byte) []byte{
		"a flipped material byte": func(b []byte) []byte { b[20] ^= 0xFF; return b },
		"a flipped index byte":    func(b []byte) []byte { b[1+8+len(renderingSealID)+4] ^= 0xFF; return b },
		"a flipped checksum byte": func(b []byte) []byte { b[len(b)-1] ^= 0xFF; return b },
		"a wrong version byte":    func(b []byte) []byte { b[0] = 0x02; return b },
		"a truncated envelope":    func(b []byte) []byte { return b[:len(b)-1] },
		"an empty envelope":       func([]byte) []byte { return nil },
		"a length field that overruns": func(b []byte) []byte {
			b[1] = 0xFF
			return b
		},
	}

	for name, damage := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			damaged := damage(bytes.Clone(good))
			got, err := ImportShare(damaged)
			if err == nil {
				t.Fatalf("ImportShare accepted %s", name)
			}
			if !errors.Is(err, ErrInvalidShare) && !errors.Is(err, ErrMalformedID) {
				t.Fatalf("ImportShare error = %v, want ErrInvalidShare or ErrMalformedID", err)
			}
			if !got.IsZero() {
				t.Fatal("ImportShare returned material alongside an error")
			}
			assertNoMaterial(t, "ImportShare error", err.Error(), nil, share.Material())
		})
	}
}

func TestNewShareAndSealedKeyValidation(t *testing.T) {
	t.Parallel()

	seal := mustRenderingSealID(t)

	t.Run("a share with no material", func(t *testing.T) {
		t.Parallel()
		if _, err := NewShare(seal, FirstGeneration, 1, nil); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("error = %v, want ErrInvalidShare", err)
		}
	})
	t.Run("a share of the wrong length", func(t *testing.T) {
		t.Parallel()
		if _, err := NewShare(seal, FirstGeneration, 1, make([]byte, KeySize-1)); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("error = %v, want ErrInvalidShare", err)
		}
	})
	t.Run("an all-zero share", func(t *testing.T) {
		t.Parallel()
		if _, err := NewShare(seal, FirstGeneration, 1, make([]byte, KeySize)); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("error = %v, want ErrInvalidShare", err)
		}
	})
	t.Run("a share at index zero", func(t *testing.T) {
		t.Parallel()
		material := bytes.Repeat([]byte{0x01}, KeySize)
		if _, err := NewShare(seal, FirstGeneration, 0, material); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("error = %v, want ErrInvalidShare: index 0 is the secret itself", err)
		}
	})
	t.Run("a share at generation zero", func(t *testing.T) {
		t.Parallel()
		material := bytes.Repeat([]byte{0x01}, KeySize)
		if _, err := NewShare(seal, 0, 1, material); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("error = %v, want ErrInvalidArgument", err)
		}
	})
	t.Run("a share of no seal", func(t *testing.T) {
		t.Parallel()
		material := bytes.Repeat([]byte{0x01}, KeySize)
		if _, err := NewShare(SealID{}, FirstGeneration, 1, material); !errors.Is(err, ErrInvalidShare) {
			t.Fatalf("error = %v, want ErrInvalidShare", err)
		}
	})

	t.Run("key material", func(t *testing.T) {
		t.Parallel()
		for name, b := range map[string][]byte{
			"empty":     {},
			"nil":       nil,
			"too short": make([]byte, KeySize-1),
			"too long":  make([]byte, KeySize+1),
			"all zero":  make([]byte, KeySize),
		} {
			if _, err := SealedKeyFrom(b); !errors.Is(err, ErrInvalidKeyMaterial) {
				t.Fatalf("SealedKeyFrom(%s) error = %v, want ErrInvalidKeyMaterial", name, err)
			}
		}
		good := bytes.Repeat([]byte{0x07}, KeySize)
		key, err := SealedKeyFrom(good)
		if err != nil {
			t.Fatalf("SealedKeyFrom: %v", err)
		}
		// Copied, not aliased: the caller must be able to zeroize its own
		// buffer without zeroizing the key.
		clear(good)
		if key.IsZero() {
			t.Fatal("SealedKeyFrom aliased the caller's buffer")
		}
		key.Destroy()
	})
}

func TestNewSealedKeyIsRandom(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 64)
	for range 64 {
		key, err := NewSealedKey()
		if err != nil {
			t.Fatalf("NewSealedKey: %v", err)
		}
		if err := key.Validate(); err != nil {
			t.Fatalf("a freshly minted key does not validate: %v", err)
		}
		seen[string(key.Bytes())] = struct{}{}
		key.Destroy()
	}
	if len(seen) != 64 {
		t.Fatalf("64 minted keys produced %d distinct values", len(seen))
	}
}

// ---- helpers ----

func mustRenderingSealID(t *testing.T) SealID {
	t.Helper()

	id, err := ParseSealID(renderingSealID)
	if err != nil {
		t.Fatalf("ParseSealID: %v", err)
	}
	return id
}

// renderingFixtures returns a key and a share with distinctive material, so
// that a substring search for the material means something.
func renderingFixtures(t *testing.T) (SealedKey, Share) {
	t.Helper()

	material := make([]byte, KeySize)
	for i := range material {
		material[i] = byte(0xC0 + i)
	}
	key, err := SealedKeyFrom(material)
	if err != nil {
		t.Fatalf("SealedKeyFrom: %v", err)
	}

	shareMaterial := make([]byte, KeySize)
	for i := range shareMaterial {
		shareMaterial[i] = byte(0x40 + i)
	}
	share, err := NewShare(mustRenderingSealID(t), FirstGeneration, renderingIndex, shareMaterial)
	if err != nil {
		t.Fatalf("NewShare: %v", err)
	}
	return key, share
}

// assertNoMaterial fails if text contains any of the secrets, in any
// encoding a careless interpolation would produce, or KeySize in decimal.
func assertNoMaterial(t *testing.T, label, text string, secrets ...[]byte) {
	t.Helper()

	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		for encoding, rendered := range map[string]string{
			"raw bytes":       string(secret),
			"lowercase hex":   hex.EncodeToString(secret),
			"uppercase hex":   strings.ToUpper(hex.EncodeToString(secret)),
			"standard base64": base64.StdEncoding.EncodeToString(secret),
			"url base64":      base64.URLEncoding.EncodeToString(secret),
			"go byte slice":   fmt.Sprintf("%v", secret),
			"go hex dump":     fmt.Sprintf("%x", secret),
		} {
			if strings.Contains(text, rendered) {
				t.Fatalf("%s leaked the material as %s: %q", label, encoding, text)
			}
		}
	}
	if n := strconv.Itoa(KeySize); strings.Contains(text, n) {
		t.Fatalf("%s leaked the material's length (%s): %q", label, n, text)
	}
}
