package embassy

import "strings"

// The decision-14 secret selector: one Embassy mount may serve several projects,
// so the reverse secret is chosen by the signed `project_id` rather than being
// deployment-wide. Every HMAC direction — inbound verify, outbound sign, script
// fetch — goes through here, which is why it is one file and not a config detail.

func validProjectID(projectID string) bool {
	return tenantIDPattern.MatchString(projectID) && !strings.EqualFold(projectID, nilUUID)
}

// secretForProject is the one selector used by every HMAC direction. In
// single-secret mode project_id remains optional for legacy callbacks/probes.
func (c *Config) secretForProject(projectID string) (string, bool) {
	if len(c.Secrets) == 0 {
		return c.Secret, c.Secret != ""
	}
	if !validProjectID(projectID) {
		return "", false
	}
	if secret, ok := c.Secrets[projectID]; ok && strings.TrimSpace(secret) != "" {
		return secret, true
	}
	for configuredID, secret := range c.Secrets {
		if strings.EqualFold(configuredID, projectID) && strings.TrimSpace(secret) != "" {
			return secret, true
		}
	}
	return "", false
}

func (c *Config) outboundSecret(projectID string) (string, error) {
	if !c.actionEnabled() {
		return "", publicError("ACTION_PLANE_DISABLED")
	}
	if len(c.Secrets) == 0 {
		return c.Secret, nil
	}
	secret, ok := c.secretForProject(projectID)
	if !ok {
		return "", publicError("ACTION_PROJECT_UNKNOWN")
	}
	return secret, nil
}
