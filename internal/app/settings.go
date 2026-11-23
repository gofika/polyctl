package app

import (
	"fmt"

	"github.com/gofika/polyctl/internal/platform"
)

// Setting resolves a per-platform setting by the precedence every setting
// follows: the flag's value when it was given (non-empty), else
// profiles.<profile>.defaults.<platform>.<key>, else
// defaults.<platform>.<key>, else "".
func (rt *Runtime) Setting(profile string, id platform.ID, key, flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	v, err := cfg.DefaultString(profile, id, key)
	if err != nil {
		return "", UsageErrf("config.yaml: %v", err)
	}
	return v, nil
}

// RequireSetting is Setting for a value that has no built-in default:
// missing everywhere, it is a usage error that names the flag to pass and
// the config key to set.
func (rt *Runtime) RequireSetting(profile string, id platform.ID, key, flag, flagValue string) (string, error) {
	v, err := rt.Setting(profile, id, key, flagValue)
	if err != nil || v != "" {
		return v, err
	}
	return "", UsageErrf("%s is required: pass --%s, or set defaults.%s.%s (or profiles.%s.defaults.%s.%s) in config.yaml", key, flag, id, key, profile, id, key)
}

// SettingList resolves a list setting like Setting: the flag's values when
// given, else the configured default list.
func (rt *Runtime) SettingList(profile string, id platform.ID, key string, flagValues []string) ([]string, error) {
	if len(flagValues) > 0 {
		return flagValues, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	v, err := cfg.DefaultStrings(profile, id, key)
	if err != nil {
		return nil, UsageErrf("config.yaml: %v", err)
	}
	return v, nil
}

// ResourceName renders the naming template naming.<key> with vars, or the
// explicit name when one was given (a flag that overrides the convention).
func (rt *Runtime) ResourceName(key, explicit string, vars map[string]string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	name, err := cfg.Name(key, vars)
	if err != nil {
		return "", fmt.Errorf("naming.%s: %w", key, err)
	}
	return name, nil
}
