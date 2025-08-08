package oauth2_authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

type Config struct {
	Groups      []string `json:"groups"`
	GroupsClaim string   `json:"groupsClaim"`
}

func CreateConfig() *Config {
	return &Config{
		GroupsClaim: "groups", // default claim name
	}
}

type Oauth2authz struct {
	next        http.Handler
	groups      []string
	groupsClaim string
	name        string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Groups) == 0 {
		return nil, fmt.Errorf("at least one group is required")
	}
	if config.GroupsClaim == "" {
		config.GroupsClaim = "groups"
	}
	return &Oauth2authz{
		next:        next,
		groups:      config.Groups,
		groupsClaim: config.GroupsClaim,
		name:        name,
	}, nil
}

func (a *Oauth2authz) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(rw, "Unauthorized: missing bearer token", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		http.Error(rw, "Unauthorized: malformed token", http.StatusUnauthorized)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(rw, "Unauthorized: invalid token encoding", http.StatusUnauthorized)
		return
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		http.Error(rw, "Unauthorized: invalid token payload", http.StatusUnauthorized)
		return
	}

	groupsRaw, ok := claims[a.groupsClaim]
	if !ok {
		http.Error(rw, fmt.Sprintf("Forbidden: no %q claim in token", a.groupsClaim), http.StatusForbidden)
		return
	}

	groupList, ok := groupsRaw.([]any)
	if !ok {
		http.Error(rw, fmt.Sprintf("Forbidden: %q claim malformed", a.groupsClaim), http.StatusForbidden)
		return
	}

	for _, g := range groupList {
		if groupStr, ok := g.(string); ok {
			if slices.Contains(a.groups, groupStr) {
				a.next.ServeHTTP(rw, req)
				return
			}
		}
	}

	http.Error(rw, "Forbidden: none of the required groups found", http.StatusForbidden)
}
