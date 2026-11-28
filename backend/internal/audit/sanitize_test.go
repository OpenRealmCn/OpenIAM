package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeRedactsVariantCredentialKeys(t *testing.T) {
	m := toSanitizedJSONMap(map[string]any{
		"smtp.password":     "p",
		"access_key_secret": "s",
		"app_secret":        "s",
		"api_key":           "k",
		"recovery_codes":    []string{"a", "b"},
		"display_name":      "visible",
		"domain_code":       "default",
		"nested":            []any{map[string]any{"auth_token": "t", "name": "n"}},
	})
	for _, k := range []string{"smtp.password", "access_key_secret", "app_secret", "api_key", "recovery_codes"} {
		assert.Equal(t, "***REDACTED***", m[k], k)
	}
	assert.Equal(t, "visible", m["display_name"])
	assert.Equal(t, "default", m["domain_code"])
	nested := m["nested"].([]any)[0].(map[string]any)
	assert.Equal(t, "***REDACTED***", nested["auth_token"])
	assert.Equal(t, "n", nested["name"])

	arr := toSanitizedJSONMap([]any{map[string]any{"password": "x"}})
	assert.Equal(t, "***REDACTED***", arr["value"].([]any)[0].(map[string]any)["password"])
}
