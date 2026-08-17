package embassy

import (
	"regexp"
	"strings"
)

// TenantContext is the trusted tenant tuple the HOST stamped outside any
// model-authored params and signed into the invocation bytes. A script trusts it
// because of the signature; params can never select or override it.
//
// ScopeValue may legitimately be empty (credential/id/slug-scoped tenants).
type TenantContext struct {
	ID         string
	Slug       string
	ScopeValue string
}

var (
	tenantIDPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tenantSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$`)
)

const nilUUID = "00000000-0000-0000-0000-000000000000"

var tenantFields = []string{"tenant_id", "tenant_slug", "tenant_scope_value"}

// validateTenantContext enforces the all-or-nothing tuple rule on KEY PRESENCE,
// not on emptiness: a flat project omits all three fields (preserving its
// pre-tenant signed bytes), a tenant-bound invocation carries a non-empty
// tenant_id AND tenant_slug. Any partial tuple is a refusal.
func validateTenantContext(raw map[string]any, requireTenant bool) (*TenantContext, error) {
	var provided []string
	for _, field := range tenantFields {
		if _, present := raw[field]; present {
			provided = append(provided, field)
		}
	}
	if len(provided) == 0 {
		if requireTenant {
			return nil, invalidRequest("tenant context is required for this Embassy deployment")
		}
		return nil, nil
	}

	values := map[string]string{}
	var notStrings []string
	for _, field := range provided {
		s, ok := raw[field].(string)
		if !ok {
			notStrings = append(notStrings, field)
			continue
		}
		values[field] = s
	}
	if len(notStrings) > 0 {
		return nil, invalidRequest("tenant field(s) must be strings: %s", strings.Join(notStrings, ", "))
	}
	for _, field := range provided {
		// No env-bound field may contain NUL — it truncates in every subprocess
		// mechanism the contract allows, silently changing the tenant.
		if strings.ContainsRune(values[field], 0) {
			return nil, invalidRequest("tenant field(s) must not contain NUL bytes")
		}
	}

	id, slug, scopeValue := values["tenant_id"], values["tenant_slug"], values["tenant_scope_value"]

	switch {
	case id == "" && slug == "" && scopeValue == "":
		// Present-but-all-empty is a broken sender, not a flat project: a flat
		// project OMITS the keys.
		return nil, invalidRequest("flat invocation must omit tenant fields")
	case id == "":
		return nil, invalidRequest("tenant_id missing for tenant-bound invocation")
	case slug == "":
		return nil, invalidRequest("tenant_slug missing for tenant-bound invocation")
	case !tenantIDPattern.MatchString(id):
		return nil, invalidRequest("tenant_id must be a UUID")
	case strings.EqualFold(id, nilUUID):
		return nil, invalidRequest("tenant_id must not be the nil UUID")
	case !tenantSlugPattern.MatchString(slug):
		return nil, invalidRequest("tenant_slug is invalid")
	}

	return &TenantContext{ID: id, Slug: slug, ScopeValue: scopeValue}, nil
}
