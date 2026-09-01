package embassy

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, raw string) any {
	t.Helper()
	object, err := decodeJSONObject([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return object
}

func TestValidateParams(t *testing.T) {
	tests := []struct {
		name    string
		params  string
		schema  string
		wantErr string
	}{
		{
			name:   "happy path",
			params: `{"email":"x@acme.com","count":3,"ratio":1.5,"flag":true,"tags":["a","b"]}`,
			schema: `{"email":{"type":"string"},"count":{"type":"integer"},"ratio":{"type":"number"},"flag":{"type":"boolean"},"tags":{"type":"string[]"}}`,
		},
		{
			name:    "an array schema is a hard refusal",
			params:  `{"email":"x@acme.com"}`,
			schema:  `[{"name":"email"}]`,
			wantErr: "schema must be a JSON object, got array",
		},
		{
			name:    "unknown param",
			params:  `{"email":"x@acme.com","sneaky":"1"}`,
			schema:  `{"email":{"type":"string"}}`,
			wantErr: "unknown param(s): sneaky",
		},
		{
			name:    "required defaults to true",
			params:  `{}`,
			schema:  `{"email":{"type":"string"}}`,
			wantErr: "missing required param: email",
		},
		{
			name:   "explicitly optional may be absent",
			params: `{}`,
			schema: `{"email":{"type":"string","required":false}}`,
		},
		{
			name:    "a boolean is not an integer",
			params:  `{"count":true}`,
			schema:  `{"count":{"type":"integer"}}`,
			wantErr: "expected integer",
		},
		{
			name:    "a boolean is not a number",
			params:  `{"ratio":false}`,
			schema:  `{"ratio":{"type":"number"}}`,
			wantErr: "expected number",
		},
		{
			name:    "a float is not an integer",
			params:  `{"count":1.5}`,
			schema:  `{"count":{"type":"integer"}}`,
			wantErr: "expected integer",
		},
		{
			name:    "unsupported type",
			params:  `{"blob":"x"}`,
			schema:  `{"blob":{"type":"object"}}`,
			wantErr: "unsupported type",
		},
		{
			name:    "reserved tenant param",
			params:  `{"tenant_id":"22222222-2222-2222-2222-222222222222"}`,
			schema:  `{"tenant_id":{"type":"string"}}`,
			wantErr: "reserved param(s): tenant_id",
		},
		{
			name:    "reserved tenant param is case-insensitive in the schema alone",
			params:  `{}`,
			schema:  `{"RC_Tenant_Slug":{"type":"string"}}`,
			wantErr: "reserved param(s): RC_Tenant_Slug",
		},
		{
			name:    "every rc tenant prefix spelling is reserved",
			params:  `{"rc_tenant_custom":"sneaky"}`,
			schema:  `{"rc_tenant_custom":{"type":"string"}}`,
			wantErr: "reserved param(s): rc_tenant_custom",
		},
		{
			name:    "principal selectors are reserved in params",
			params:  `{"principal_kind":"sneaky"}`,
			schema:  `{"principal_kind":{"type":"string"}}`,
			wantErr: "reserved param(s): principal_kind",
		},
		{
			name:    "every rc principal prefix spelling is reserved in the schema",
			params:  `{}`,
			schema:  `{"RC_Principal_Custom":{"type":"string"}}`,
			wantErr: "reserved param(s): RC_Principal_Custom",
		},
		{
			name:    "a missing schema fails closed",
			params:  `{"email":"x"}`,
			schema:  ``,
			wantErr: "schema is missing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var schema any
			if test.schema != "" {
				var value any
				if err := json.Unmarshal([]byte(test.schema), &value); err != nil {
					t.Fatal(err)
				}
				schema = value
			}
			_, err := validateParams(decode(t, test.params), schema)
			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.(*Error).Message, test.wantErr)):
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			case test.wantErr != "":
				refusal := err.(*Error)
				if refusal.Status != 422 || refusal.Class != ClassSchemaViolation {
					t.Fatalf("refusal = %d %s", refusal.Status, refusal.Class)
				}
			}
		})
	}
}

// Integers survive as int64 rather than round-tripping through float64.
func TestValidateParamsNormalizesTypes(t *testing.T) {
	params, err := validateParams(
		decode(t, `{"count":9007199254740993,"tags":["a"]}`),
		decode(t, `{"count":{"type":"integer"},"tags":{"type":"string[]"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := params["count"].(int64); !ok || got != 9007199254740993 {
		t.Fatalf("count = %#v", params["count"])
	}
	if got, ok := params["tags"].([]string); !ok || got[0] != "a" {
		t.Fatalf("tags = %#v", params["tags"])
	}
}
