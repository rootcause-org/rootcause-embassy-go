package embassy

import (
	"encoding/json"
	"sort"
	"strings"
)

// Wire param types. Only `type` and `required` cross the wire — host-side Layer-1
// constraints (format/pattern/enum) are deliberately not sent.
var schemaTypes = map[string]bool{
	"string": true, "integer": true, "number": true, "boolean": true, "string[]": true,
}

// Reserved names carry host-stamped scope. Params select a target inside that
// scope, so these are refused in BOTH params and schema, case-insensitively.
var reservedTenantParams = map[string]bool{
	"tenant_id": true, "tenant_slug": true, "tenant_scope_value": true,
}

func isReservedTenantParam(name string) bool {
	canonical := strings.ToLower(name)
	return reservedTenantParams[canonical] || strings.HasPrefix(canonical, "rc_tenant_") ||
		canonical == "principal_kind" || canonical == "principal_external_id" ||
		strings.HasPrefix(canonical, "principal_claim_") ||
		strings.HasPrefix(canonical, "rc_principal_")
}

type paramSpec struct {
	Type     string
	Required bool
}

// validateParams re-validates the invocation's params against the schema it
// carries. Defense in depth: the host already validated at propose time, but an
// Embassy never trusts the wire.
//
// Map form ONLY (object keyed by param name). An array schema is a hard 422 — the
// JSON-Schema `properties` shape is not contract.
//
// Returns params normalized for the script: json.Number collapsed to int64/float64,
// string arrays to []string. The map is freshly built per run, so a script cannot
// mutate state another run reads.
func validateParams(rawParams, rawSchema any) (map[string]any, error) {
	specs, err := normalizeSchema(rawSchema)
	if err != nil {
		return nil, err
	}

	params := map[string]any{}
	if rawParams != nil {
		m, ok := rawParams.(map[string]any)
		if !ok {
			return nil, schemaViolation("params must be an object")
		}
		params = m
	}

	var reserved []string
	for name := range params {
		if isReservedTenantParam(name) {
			reserved = append(reserved, name)
		}
	}
	for name := range specs {
		if isReservedTenantParam(name) && !contains(reserved, name) {
			reserved = append(reserved, name)
		}
	}
	if len(reserved) > 0 {
		sort.Strings(reserved)
		return nil, schemaViolation("tenant and principal scope are host-owned; reserved param(s): %s", strings.Join(reserved, ", "))
	}

	var unknown []string
	for name := range params {
		if _, ok := specs[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, schemaViolation("unknown param(s): %s", strings.Join(unknown, ", "))
	}

	out := make(map[string]any, len(specs))
	for name, spec := range specs {
		value, present := params[name]
		if !present {
			if spec.Required {
				return nil, schemaViolation("missing required param: %s", name)
			}
			continue
		}
		normalized, err := checkType(name, value, spec.Type)
		if err != nil {
			return nil, err
		}
		out[name] = normalized
	}
	return out, nil
}

func normalizeSchema(raw any) (map[string]paramSpec, error) {
	switch raw.(type) {
	case nil:
		return nil, schemaViolation("schema is missing")
	case []any:
		return nil, schemaViolation("schema must be a JSON object, got array")
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return nil, schemaViolation("schema must be a JSON object")
	}

	specs := make(map[string]paramSpec, len(object))
	for name, rawSpec := range object {
		spec, ok := rawSpec.(map[string]any)
		if !ok {
			return nil, schemaViolation("param %s: spec must be an object", name)
		}
		typeName, _ := spec["type"].(string)
		if !schemaTypes[typeName] {
			return nil, schemaViolation("param %s: unsupported type %q", name, typeName)
		}
		// Required defaults to TRUE: a param schema is required unless explicitly
		// marked optional. Fail closed on absence.
		required := true
		if value, present := spec["required"]; present {
			if b, ok := value.(bool); ok {
				required = b
			}
		}
		specs[name] = paramSpec{Type: typeName, Required: required}
	}
	return specs, nil
}

func checkType(name string, value any, typeName string) (any, error) {
	switch typeName {
	case "string":
		if s, ok := value.(string); ok {
			return s, nil
		}
	case "boolean":
		if b, ok := value.(bool); ok {
			return b, nil
		}
	case "integer":
		// A bool is never a number, and 1.5 is never an integer. json.Number keeps
		// the wire spelling so a big int64 survives the round-trip intact.
		if n, ok := value.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				return i, nil
			}
		}
	case "number":
		if n, ok := value.(json.Number); ok {
			if f, err := n.Float64(); err == nil {
				return f, nil
			}
		}
	case "string[]":
		if list, ok := value.([]any); ok {
			out := make([]string, 0, len(list))
			for _, element := range list {
				s, ok := element.(string)
				if !ok {
					return nil, schemaViolation("param %s: expected string[], got a non-string element", name)
				}
				out = append(out, s)
			}
			return out, nil
		}
	}
	return nil, schemaViolation("param %s: expected %s, got %s", name, typeName, jsonKind(value))
}

func jsonKind(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		_ = v
		return "unknown"
	}
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
