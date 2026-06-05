// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

// applyProbeOverrides applies CLI flag overrides to an in-progress probe config.
func applyProbeOverrides(cfg *ClientConfig, overrides ClientConfigOverrides) error {
	if len(overrides.Values) > 0 {
		if err := applyClientConfigOverrideValues(cfg, overrides.Values); err != nil {
			return err
		}
	}
	return nil
}

// LoadProbeClientConfig loads a client config file (TOML or JSON), applies
// overrides, and finalizes in probe mode (no resolver file required).
func LoadProbeClientConfig(filename string, overrides ClientConfigOverrides) (ClientConfig, error) {
	cfg, err := loadClientConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	if err := applyProbeOverrides(&cfg, overrides); err != nil {
		return cfg, err
	}
	return finalizeClientConfigOpts(cfg, false)
}

// LoadProbeClientConfigFromJSONBase64 is the json-base64 analogue.
func LoadProbeClientConfigFromJSONBase64(encoded string, overrides ClientConfigOverrides) (ClientConfig, error) {
	cfg, err := loadClientConfigFromJSONBase64(encoded)
	if err != nil {
		return cfg, err
	}
	if err := applyProbeOverrides(&cfg, overrides); err != nil {
		return cfg, err
	}
	return finalizeClientConfigOpts(cfg, false)
}

// NewProbeClientConfigFromOverrides builds a probe config from engine defaults +
// flag overrides only (no config file).
func NewProbeClientConfigFromOverrides(overrides ClientConfigOverrides) (ClientConfig, error) {
	cfg := defaultClientConfig()
	if err := applyProbeOverrides(&cfg, overrides); err != nil {
		return cfg, err
	}
	return finalizeClientConfigOpts(cfg, false)
}
