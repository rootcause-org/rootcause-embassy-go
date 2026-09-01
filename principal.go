package embassy

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// PrincipalContext is the host-resolved identity assertion signed into one
// action invocation. It is deliberately separate from model-authored params.
type PrincipalContext struct {
	kind       string
	externalID string
	claims     map[string]any
}

// Kind identifies the principal namespace selected by the host.
func (p *PrincipalContext) Kind() string { return p.kind }

// ExternalID is the host's identifier for this principal in its namespace.
func (p *PrincipalContext) ExternalID() string { return p.externalID }

// Claim returns one typed host-resolved claim. The returned value belongs to
// this invocation; callers cannot alter the stored assertion.
func (p *PrincipalContext) Claim(name string) (any, bool) {
	value, ok := p.claims[name]
	return clonePrincipalClaim(value), ok
}

// Claims returns a copy so action code cannot mutate the trusted assertion.
func (p *PrincipalContext) Claims() map[string]any {
	claims := make(map[string]any, len(p.claims))
	for name, value := range p.claims {
		claims[name] = clonePrincipalClaim(value)
	}
	return claims
}

var principalClaimName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// validatePrincipal decodes the optional host assertion after signature
// verification. A missing principal is intentionally distinct from an empty one.
func validatePrincipal(raw map[string]any) (*PrincipalContext, error) {
	value, present := raw["principal"]
	if !present {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, invalidRequest("principal must be an object")
	}

	kind, kindOK := object["kind"].(string)
	externalID, externalIDOK := object["external_id"].(string)
	claims, claimsOK := object["claims"].(map[string]any)
	if !kindOK || kind == "" || !externalIDOK || externalID == "" || !claimsOK {
		return nil, invalidRequest("principal requires non-empty kind, external_id, and claims")
	}
	if strings.ContainsRune(kind, 0) || strings.ContainsRune(externalID, 0) {
		return nil, invalidRequest("principal fields must not contain NUL bytes")
	}

	normalized := make(map[string]any, len(claims))
	for name, value := range claims {
		if !principalClaimName.MatchString(name) {
			return nil, invalidRequest("principal claim name is invalid: %s", name)
		}
		claim, err := normalizePrincipalClaim(name, value)
		if err != nil {
			return nil, err
		}
		normalized[name] = claim
	}
	return &PrincipalContext{kind: kind, externalID: externalID, claims: normalized}, nil
}

func normalizePrincipalClaim(name string, value any) (any, error) {
	switch value := value.(type) {
	case string:
		if strings.ContainsRune(value, 0) {
			return nil, invalidRequest("principal claim %s must not contain NUL bytes", name)
		}
		return value, nil
	case json.Number:
		integer, err := value.Int64()
		if err != nil {
			return nil, invalidRequest("principal claim %s must be an integer", name)
		}
		return integer, nil
	case []any:
		return normalizePrincipalArray(name, value)
	default:
		return nil, invalidRequest("principal claim %s must be a string, integer, or homogeneous array", name)
	}
}

func normalizePrincipalArray(name string, values []any) (any, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	switch values[0].(type) {
	case string:
		out := make([]string, 0, len(values))
		for _, value := range values {
			s, ok := value.(string)
			if !ok || strings.ContainsRune(s, 0) {
				return nil, invalidRequest("principal claim %s must be a homogeneous string or integer array without NUL bytes", name)
			}
			out = append(out, s)
		}
		return out, nil
	case json.Number:
		out := make([]int64, 0, len(values))
		for _, value := range values {
			number, ok := value.(json.Number)
			if !ok {
				return nil, invalidRequest("principal claim %s must be a homogeneous string or integer array", name)
			}
			integer, err := number.Int64()
			if err != nil {
				return nil, invalidRequest("principal claim %s must be an integer", name)
			}
			out = append(out, integer)
		}
		return out, nil
	default:
		return nil, invalidRequest("principal claim %s must be a homogeneous string or integer array", name)
	}
}

func clonePrincipalClaim(value any) any {
	switch value := value.(type) {
	case []string:
		return append([]string(nil), value...)
	case []int64:
		return append([]int64(nil), value...)
	default:
		return value
	}
}

const principalEnvPrefix = "RC_PRINCIPAL_"

// principalEnvironment builds the exact virtual environment for one invocation.
// The trampoline clears it before and after every action run.
func principalEnvironment(principal *PrincipalContext) map[string]string {
	if principal == nil {
		return nil
	}
	environment := map[string]string{
		principalEnvPrefix + "KIND":        principal.kind,
		principalEnvPrefix + "EXTERNAL_ID": principal.externalID,
	}
	for _, name := range sortedKeys(principal.claims) {
		environment[principalEnvPrefix+"CLAIM_"+strings.ToUpper(name)] = principalClaimEnvValue(principal.claims[name])
	}
	return environment
}

func principalClaimEnvValue(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case int64:
		return strconv.FormatInt(value, 10)
	default:
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
}
