//
// Copyright 2026 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redaction

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeScanner reports a fixed set of findings, so the engine's walk, rewrite and
// convergence behaviour can be tested without depending on the real ruleset.
type fakeScanner struct {
	findings []Finding
	// requirePresent only reports findings whose secret actually appears in the
	// scanned text, which is how a real detector behaves.
	requirePresent bool
	calls          int
}

func (f *fakeScanner) Scan(ctx context.Context, text string) ([]Finding, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !f.requirePresent {
		return f.findings, nil
	}
	var out []Finding
	for _, fi := range f.findings {
		if strings.Contains(text, fi.Secret) {
			out = append(out, fi)
		}
	}
	return out, nil
}

func TestRedact(t *testing.T) {
	testCases := []struct {
		name     string
		doc      string
		findings []Finding
		opts     []Option
		// reportAlways makes the fake scanner report its findings even when the
		// secret does not appear in the scanned text, to exercise the engine's
		// handling of findings it cannot attribute to any leaf.
		reportAlways     bool
		wantErr          error
		wantUnchanged    bool // output must be byte-identical to the input
		wantReplacements int
		wantByRule       map[string]int
		wantUnlocated    map[string]int
		mustNotContain   []string
		mustContain      []string
	}{
		{
			name:          "no findings returns the input verbatim",
			doc:           `{"data":{"a":"hello world","n":1}}`,
			wantUnchanged: true,
		},
		{
			name:             "secret in a nested leaf is replaced",
			doc:              `{"data":{"raw_session":{"main":[{"content":"run FAKE-AWS-KEY-NOT-A-REAL-PATTERN now"}]},"keep":"untouched"}}`,
			findings:         []Finding{{RuleID: "aws-access-token", Secret: "FAKE-AWS-KEY-NOT-A-REAL-PATTERN"}},
			wantReplacements: 1,
			wantByRule:       map[string]int{"aws-access-token": 1},
			mustNotContain:   []string{"FAKE-AWS-KEY-NOT-A-REAL-PATTERN"},
			mustContain:      []string{"[REDACTED:aws-access-token]", "untouched", "run ", " now"},
		},
		{
			name:             "same secret across three leaves",
			doc:              `{"a":"x SEC x","b":{"c":"SEC"},"d":["SEC"]}`,
			findings:         []Finding{{RuleID: "r1", Secret: "SEC"}},
			wantReplacements: 3,
			wantByRule:       map[string]int{"r1": 3},
			mustNotContain:   []string{`"SEC"`},
		},
		{
			name:             "secret twice in one leaf",
			doc:              `{"a":"SEC and SEC again"}`,
			findings:         []Finding{{RuleID: "r1", Secret: "SEC"}},
			wantReplacements: 2,
			wantByRule:       map[string]int{"r1": 2},
			mustNotContain:   []string{"SEC and"},
		},
		{
			name:             "escapes and non-ascii survive",
			doc:              `{"a":"line1\nSEC\ttab \"quoted\" <b> café 🚀"}`,
			findings:         []Finding{{RuleID: "r1", Secret: "SEC"}},
			wantReplacements: 1,
			mustNotContain:   []string{`\u003c`, `"SEC`},
			mustContain:      []string{`line1\n`, `\ttab`, `\"quoted\"`, "<b>", "café", "🚀"},
		},
		{
			name:             "severed escape sequence drops the whole leaf",
			doc:              `{"a":"before\nSEC after"}`,
			findings:         []Finding{{RuleID: "r1", Secret: "nSEC"}},
			wantReplacements: 1,
			mustNotContain:   []string{"before", "after"},
			mustContain:      []string{"[REDACTED:r1]"},
		},
		{
			// A rule whose character class allows `\` can capture the backslash
			// of the escape sequence that follows the secret inside a JSON string
			// leaf (the jwt rule does, before a `\"`). Replacing that trailing
			// backslash cuts the escape in half, the leaf stops decoding, and the
			// fail-closed guard throws away the surrounding context — which is the
			// bug. The secret must be normalised before it is searched for.
			name:             "trailing backslash captured from an escape sequence is trimmed",
			doc:              `{"a":"x JWT\"y"}`,
			findings:         []Finding{{RuleID: "r1", Secret: `JWT\`}},
			wantReplacements: 1,
			wantByRule:       map[string]int{"r1": 1},
			mustNotContain:   []string{"JWT"},
			mustContain:      []string{`x [REDACTED:r1]\"y`},
		},
		{
			// The same escape capture, with the whole `\n` sequence reported as
			// part of the secret: replacing it would delete the line break.
			name:             "trailing escape sequence captured from the leaf is trimmed",
			doc:              `{"a":"x JWT\nnext"}`,
			findings:         []Finding{{RuleID: "r1", Secret: `JWT\n`}},
			wantReplacements: 1,
			wantByRule:       map[string]int{"r1": 1},
			mustNotContain:   []string{"JWT"},
			mustContain:      []string{`x [REDACTED:r1]\nnext`},
		},
		{
			// The greedy group can swallow more than one escape: a token followed
			// by a CRLF or a blank line reports both escapes. Trimming only the
			// last one leaves the secret ending on the other, and the rewriter then
			// deletes that line break instead.
			name:             "two escapes captured from the leaf are trimmed together",
			doc:              `{"a":"x JWT\n\nnext"}`,
			findings:         []Finding{{RuleID: "r1", Secret: `JWT\n\n`}},
			wantReplacements: 1,
			wantByRule:       map[string]int{"r1": 1},
			mustNotContain:   []string{"JWT"},
			mustContain:      []string{`x [REDACTED:r1]\n\nnext`},
		},
		{
			name:             "a CRLF captured from the leaf keeps its carriage return",
			doc:              `{"a":"x JWT\r\nnext"}`,
			findings:         []Finding{{RuleID: "r1", Secret: `JWT\r\n`}},
			wantReplacements: 1,
			wantByRule:       map[string]int{"r1": 1},
			mustNotContain:   []string{"JWT"},
			mustContain:      []string{`x [REDACTED:r1]\r\nnext`},
		},
		{
			name:     "protected path is left alone and recorded",
			doc:      `{"keepme":"SEC","other":"plain"}`,
			findings: []Finding{{RuleID: "r1", Secret: "SEC"}},
			opts: []Option{WithPathFilter(func(p string) bool {
				return p != "/keepme"
			})},
			wantUnchanged: true,
			wantUnlocated: map[string]int{"r1": 1},
		},
		{
			name:          "finding present nowhere is classified as an artifact",
			doc:           `{"a":"plain"}`,
			findings:      []Finding{{RuleID: "r1", Secret: "NOT-IN-DOC"}},
			reportAlways:  true,
			wantUnchanged: true,
			wantUnlocated: map[string]int{"r1": 1},
		},
		{
			// A finding the engine cannot attribute to a leaf is recorded and
			// then left out of the following passes, so the loop still converges
			// around the findings it can rewrite.
			name: "an unlocatable finding is not chased on later passes",
			doc:  `{"keep":"SEC","other":"OTHER"}`,
			findings: []Finding{
				{RuleID: "r1", Secret: "SEC"},
				{RuleID: "r2", Secret: "OTHER"},
			},
			opts: []Option{WithPathFilter(func(p string) bool {
				return p != "/keep"
			})},
			wantReplacements: 1,
			wantByRule:       map[string]int{"r2": 1},
			wantUnlocated:    map[string]int{"r1": 1},
			mustContain:      []string{`"SEC"`, "[REDACTED:r2]"},
		},
		{
			name:     "placeholder that keeps matching does not converge",
			doc:      `{"a":"SEC"}`,
			findings: []Finding{{RuleID: "r1", Secret: "SEC"}},
			// A custom placeholder with no recogniser: the engine cannot tell its
			// own output apart from a secret, so it rewrites it forever. This is
			// the backstop that stops that being an infinite loop.
			opts: []Option{WithPlaceholder(func(string) string {
				return "SEC"
			}, nil)},
			wantErr: ErrNotConverged,
		},
		{
			// 1e400 is valid JSON but out of float64 range: every decoder on the
			// path has to keep numbers in their textual form, or an honest document
			// gets refused over a number nobody was going to scan anyway.
			name:             "numbers keep their exact representation",
			doc:              `{"a":"SEC","big":12345678901234567890,"exp":1e10,"f":0.30000000000000004,"huge":1e400}`,
			findings:         []Finding{{RuleID: "r1", Secret: "SEC"}},
			wantReplacements: 1,
			mustContain:      []string{"12345678901234567890", "1e10", "0.30000000000000004", "1e400"},
		},
		{
			name:    "not json",
			doc:     `not json at all`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "json array root is rejected",
			doc:     `["a"]`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "json null root is rejected",
			doc:     `null`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "trailing content is rejected",
			doc:     `{"a":"b"} trailing`,
			wantErr: ErrInvalidJSON,
		},
		{
			// Decoding keeps only the last value for a repeated key, so the secret
			// in the first one would never be scanned — and since nothing was
			// replaced, the original bytes would be handed back as clean.
			name:     "duplicate key hiding a secret is refused",
			doc:      `{"a":"SEC","a":"clean"}`,
			findings: []Finding{{RuleID: "r1", Secret: "SEC"}},
			wantErr:  ErrDuplicateKey,
		},
		{
			name:    "duplicate key nested in the transcript is refused",
			doc:     `{"data":{"raw_session":{"main":[{"content":"SEC","content":"clean"}]}}}`,
			wantErr: ErrDuplicateKey,
		},
		{
			name: "repeating a key in a sibling object is fine",
			doc:  `{"a":{"k":"x"},"b":{"k":"y"},"c":[{"k":1},{"k":2}]}`,
			// Same key name, different objects: nothing is lost, nothing to refuse.
			wantUnchanged: true,
		},
		{
			// Decoder.More reports false for a trailing bracket, so this has to be
			// caught by requiring the input to be exhausted.
			name:    "trailing closing bracket is rejected",
			doc:     `{"a":"b"}]`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "trailing closing brace is rejected",
			doc:     `{"a":"b"}}`,
			wantErr: ErrInvalidJSON,
		},
		{
			name:    "a second document is rejected",
			doc:     `{"a":"b"}{"c":"d"}`,
			wantErr: ErrInvalidJSON,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := &fakeScanner{findings: tc.findings, requirePresent: !tc.reportAlways}
			r := New(scanner, tc.opts...)

			got, report, err := r.Redact(context.Background(), []byte(tc.doc))

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, report)

			if tc.wantUnchanged {
				assert.Equal(t, tc.doc, string(got), "output must be byte-identical")
				assert.False(t, report.Changed())
				assert.Zero(t, report.Replacements)
			} else {
				assert.True(t, report.Changed())
				assert.Equal(t, tc.wantReplacements, report.Replacements)
				assert.True(t, json.Valid(got), "output must be valid JSON")
			}

			if tc.wantByRule != nil {
				assert.Equal(t, tc.wantByRule, report.ByRule)
			}
			if tc.wantUnlocated != nil {
				assert.Equal(t, tc.wantUnlocated, report.Unlocated)
			}
			for _, s := range tc.mustNotContain {
				assert.NotContains(t, string(got), s)
			}
			for _, s := range tc.mustContain {
				assert.Contains(t, string(got), s)
			}
		})
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	docs := []string{
		`{"data":{"raw_session":{"main":[{"content":"FAKE-AWS-KEY-NOT-A-REAL-PATTERN"}]}}}`,
		`{"a":"SEC","b":"no secret here"}`,
		`{"a":"line\nSEC","b":["SEC","SEC"]}`,
	}
	findings := []Finding{
		{RuleID: "aws-access-token", Secret: "FAKE-AWS-KEY-NOT-A-REAL-PATTERN"},
		{RuleID: "r1", Secret: "SEC"},
	}

	for _, doc := range docs {
		t.Run(doc, func(t *testing.T) {
			r := New(&fakeScanner{findings: findings, requirePresent: true})

			once, _, err := r.Redact(context.Background(), []byte(doc))
			require.NoError(t, err)
			twice, report, err := r.Redact(context.Background(), once)
			require.NoError(t, err)

			assert.Equal(t, string(once), string(twice))
			assert.False(t, report.Changed(), "a second pass must find nothing")
		})
	}
}

func TestRedactCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := New(&fakeScanner{findings: []Finding{{RuleID: "r1", Secret: "SEC"}}, requirePresent: true})
	got, _, err := r.Redact(ctx, []byte(`{"a":"SEC"}`))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, got)
}

// RuleIDs reports only the rules that actually redacted something, so it is
// safe to publish as a material annotation.
func TestReportRuleIDs(t *testing.T) {
	r := &Report{ByRule: map[string]int{"b": 2, "a": 1}, Unlocated: map[string]int{"c": 1}}
	assert.Equal(t, []string{"a", "b"}, r.RuleIDs())
	assert.Nil(t, (*Report)(nil).RuleIDs())
}

// TestPendingSecretsTrimsEscapeBackslashes pins the normalisation that keeps a
// greedy rule from swallowing the escape sequence following a secret inside an
// encoded JSON leaf.
func TestPendingSecretsTrimsEscapeBackslashes(t *testing.T) {
	testCases := []struct {
		name     string
		findings []Finding
		want     []secretRule
	}{
		{
			name:     "secret without an escape is unchanged",
			findings: []Finding{{RuleID: "jwt", Secret: "eyJ.sig"}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "a single character secret is unchanged",
			findings: []Finding{{RuleID: "r1", Secret: "a"}},
			want:     []secretRule{{secret: "a", ruleID: "r1"}},
		},
		{
			name:     "a single backslash is dropped",
			findings: []Finding{{RuleID: "r1", Secret: `\`}},
			want:     []secretRule{},
		},
		{
			name:     "a backslash that opens no escape is kept",
			findings: []Finding{{RuleID: "r1", Secret: `a\b`}},
			want:     []secretRule{{secret: `a\b`, ruleID: "r1"}},
		},
		{
			name:     "single trailing backslash is trimmed",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "repeated trailing backslashes are trimmed",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\\`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "a trailing newline escape is trimmed whole",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\n`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "a trailing carriage return escape is trimmed whole",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\r`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "a trailing tab escape is trimmed whole",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\t`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			// The greedy group can report several escapes at once; trimming has
			// to keep going until the secret ends on an ordinary character, or
			// the rewriter deletes the line break the remaining escape encodes.
			name:     "consecutive escapes are all trimmed",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\n\n`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "a CRLF is trimmed whole, carriage return included",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\r\n`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			name:     "an escape left behind by trailing backslashes is trimmed too",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ.sig\n\\`}},
			want:     []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
		{
			// A `\\` inside the secret is not an escape, and the trailing
			// escape-letter is not a backslash: neither may be trimmed.
			name:     "a backslash elsewhere in the secret is kept",
			findings: []Finding{{RuleID: "jwt", Secret: `eyJ\sig`}},
			want:     []secretRule{{secret: `eyJ\sig`, ruleID: "jwt"}},
		},
		{
			name:     "an escape-letter without a backslash is kept",
			findings: []Finding{{RuleID: "jwt", Secret: "eyJ.sign"}},
			want:     []secretRule{{secret: "eyJ.sign", ruleID: "jwt"}},
		},
		{
			// Trimming must not leave an empty secret behind for the rewriter to
			// search for: an empty needle matches everywhere.
			name:     "a finding that is only backslashes is dropped",
			findings: []Finding{{RuleID: "jwt", Secret: `\\`}},
			want:     []secretRule{},
		},
		{
			name:     "a finding that is only an escape is dropped",
			findings: []Finding{{RuleID: "jwt", Secret: `\n`}},
			want:     []secretRule{},
		},
		{
			name: "findings that only differ by trailing backslashes are deduplicated",
			findings: []Finding{
				{RuleID: "jwt", Secret: `eyJ.sig\\`},
				{RuleID: "jwt", Secret: "eyJ.sig"},
			},
			want: []secretRule{{secret: "eyJ.sig", ruleID: "jwt"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := pendingSecrets(tc.findings, nil, IsDefaultPlaceholder)
			assert.Equal(t, tc.want, got)
		})
	}
}
