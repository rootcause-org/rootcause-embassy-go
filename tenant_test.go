package embassy

import (
	"strings"
	"testing"
)

func TestValidateTenantContext(t *testing.T) {
	const validID = "22222222-2222-2222-2222-222222222222"

	tests := []struct {
		name          string
		body          string
		requireTenant bool
		wantSlug      string
		wantErr       string
	}{
		{
			name: "a flat project omits all three keys",
			body: `{"action_id":"a"}`,
		},
		{
			name:          "require_tenant_context refuses an absent tuple",
			body:          `{"action_id":"a"}`,
			requireTenant: true,
			wantErr:       "tenant context is required",
		},
		{
			name:     "full tuple",
			body:     `{"tenant_id":"` + validID + `","tenant_slug":"acme","tenant_scope_value":"account-42"}`,
			wantSlug: "acme",
		},
		{
			name:     "scope_value may be absent",
			body:     `{"tenant_id":"` + validID + `","tenant_slug":"acme"}`,
			wantSlug: "acme",
		},
		{
			name:     "scope_value may be empty",
			body:     `{"tenant_id":"` + validID + `","tenant_slug":"acme","tenant_scope_value":""}`,
			wantSlug: "acme",
		},
		{
			name:    "a partial tuple is a refusal",
			body:    `{"tenant_id":"` + validID + `"}`,
			wantErr: "tenant_slug missing",
		},
		{
			name:    "present-but-all-empty is a broken sender, not a flat project",
			body:    `{"tenant_id":"","tenant_slug":"","tenant_scope_value":""}`,
			wantErr: "flat invocation must omit tenant fields",
		},
		{
			name:    "a non-string tenant field",
			body:    `{"tenant_id":42,"tenant_slug":"acme"}`,
			wantErr: "must be strings",
		},
		{
			name:    "a NUL byte is refused",
			body:    `{"tenant_id":"` + validID + `","tenant_slug":"ac\u0000me"}`,
			wantErr: "NUL",
		},
		{
			name:    "a non-UUID tenant_id",
			body:    `{"tenant_id":"acme","tenant_slug":"acme"}`,
			wantErr: "tenant_id must be a UUID",
		},
		{
			name:    "the nil UUID is refused",
			body:    `{"tenant_id":"00000000-0000-0000-0000-000000000000","tenant_slug":"acme"}`,
			wantErr: "nil UUID",
		},
		{
			name:    "an invalid slug",
			body:    `{"tenant_id":"` + validID + `","tenant_slug":"Acme Corp"}`,
			wantErr: "tenant_slug is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := decodeJSONObject([]byte(test.body))
			if err != nil {
				t.Fatal(err)
			}
			tenant, err := validateTenantContext(raw, test.requireTenant)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				refusal := err.(*Error)
				if refusal.Status != 400 || refusal.Class != ClassInvalidRequest {
					t.Fatalf("refusal = %d %s", refusal.Status, refusal.Class)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch {
			case test.wantSlug == "" && tenant != nil:
				t.Fatalf("tenant = %+v, want nil", tenant)
			case test.wantSlug != "" && (tenant == nil || tenant.Slug != test.wantSlug):
				t.Fatalf("tenant = %+v, want slug %q", tenant, test.wantSlug)
			}
		})
	}
}
