package embassy

import (
	"reflect"
	"testing"
)

func TestValidatePrincipal(t *testing.T) {
	principal, err := validatePrincipal(decode(t, `{"principal":{"kind":"acme_user","external_id":"user-8f3","claims":{"user_id":"user-8f3","person_id":103,"backup_ids":["backup-7","backup-9"]}}}`).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Kind() != "acme_user" || principal.ExternalID() != "user-8f3" {
		t.Fatalf("principal = %#v", principal)
	}
	if got, ok := principal.Claim("person_id"); !ok || got != int64(103) {
		t.Fatalf("person_id = %#v", got)
	}
	claims := principal.Claims()
	claims["user_id"] = "changed"
	if got, _ := principal.Claim("user_id"); got != "user-8f3" {
		t.Fatalf("claims leaked mutation: %#v", got)
	}

	for _, body := range []string{
		`{"principal":null}`,
		`{"principal":{"kind":"","external_id":"user","claims":{}}}`,
		`{"principal":{"kind":"kind","external_id":"user","claims":{"Bad":"x"}}}`,
		`{"principal":{"kind":"kind","external_id":"user","claims":{"id":1.5}}}`,
		`{"principal":{"kind":"kind","external_id":"user","claims":{"ids":["a",2]}}}`,
		`{"principal":{"kind":"kind","external_id":"user","claims":{"id":"a\u0000b"}}}`,
	} {
		if _, err := validatePrincipal(decode(t, body).(map[string]any)); err == nil {
			t.Fatalf("validatePrincipal(%s) unexpectedly accepted", body)
		}
	}
	if principal, err := validatePrincipal(decode(t, `{}`).(map[string]any)); err != nil || principal != nil {
		t.Fatalf("absent principal = %#v, %v", principal, err)
	}
}

func TestPrincipalEnvironmentIsInvocationScoped(t *testing.T) {
	principal, err := validatePrincipal(decode(t, `{"principal":{"kind":"acme_user","external_id":"user-8f3","claims":{"person_id":103,"backup_ids":["backup-7","backup-9"]}}}`).(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	got := principalEnvironment(principal)
	want := map[string]string{
		"RC_PRINCIPAL_KIND":             "acme_user",
		"RC_PRINCIPAL_EXTERNAL_ID":      "user-8f3",
		"RC_PRINCIPAL_CLAIM_BACKUP_IDS": `["backup-7","backup-9"]`,
		"RC_PRINCIPAL_CLAIM_PERSON_ID":  "103",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
	if got := principalEnvironment(nil); len(got) != 0 {
		t.Fatalf("principal-less environment = %#v", got)
	}
}
