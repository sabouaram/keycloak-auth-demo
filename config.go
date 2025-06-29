package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/viper"
)

func ParseConf() (cfg *Config, err error) {
	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err = v.ReadInConfig(); err != nil {
		return nil, err
	}

	cfg, err = validateConfig(v)

	return cfg, err
}

type Config struct {
	KeycloakURL        string
	Realm              string
	Scheme             string
	BaseURL            string
	SAMLEntityID       string
	SAMLMetadataURL    string
	SessionSecret      string
	MaxSessionAge      int
	InsecureSkipVerify bool
}

func validateConfig(cfg *viper.Viper) (*Config, error) {
	var (
		config = &Config{}
		err    error
		scheme string
		secret string
		parsed *url.URL

		missingFields  []string
		requiredFields = []string{
			"KEYCLOAK_URL",
			"REALM",
			"SCHEME",
			"BASE_URL",
			"SAML_ENTITY_ID",
			"SAML_METADATA_URL",
		}
	)

	for _, field := range requiredFields {
		if !cfg.IsSet(field) {
			missingFields = append(missingFields, field)
		}
	}

	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing required configuration fields: %s", strings.Join(missingFields, ", "))
	}

	scheme = strings.ToLower(cfg.GetString("SCHEME"))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("invalid SCHEME: must be either 'http' or 'https'")
	}

	urlFields := map[string]string{
		"KEYCLOAK_URL":      cfg.GetString("KEYCLOAK_URL"),
		"BASE_URL":          cfg.GetString("BASE_URL"),
		"SAML_METADATA_URL": cfg.GetString("SAML_METADATA_URL"),
		"SAML_ENTITY_ID":    cfg.GetString("SAML_ENTITY_ID"),
	}

	for name, value := range urlFields {
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			return nil, fmt.Errorf("%s should not include scheme (http:// or https://)", name)
		}

		if parsed, err = url.Parse(scheme + "://" + value); err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("invalid URL format for %s: %v", name, err)
		}
	}

	if cfg.GetInt("MAX_SESSION_AGE") <= 0 {
		return nil, fmt.Errorf("MAX_SESSION_AGE must be a positive integer")
	}

	if secret = cfg.GetString("SESSION_SECRET"); len(secret) < 32 {
		return nil, fmt.Errorf("SESSION_SECRET cannot be empty or less than 32 characters")
	}

	addScheme := func(raw string) string {
		return scheme + "://" + strings.TrimSuffix(raw, "/")
	}

	config.KeycloakURL = addScheme(cfg.GetString("KEYCLOAK_URL"))
	config.Realm = cfg.GetString("REALM")
	config.Scheme = scheme
	config.BaseURL = addScheme(cfg.GetString("BASE_URL"))
	config.SAMLEntityID = addScheme(cfg.GetString("SAML_ENTITY_ID"))
	config.SAMLMetadataURL = addScheme(cfg.GetString("SAML_METADATA_URL"))
	config.SessionSecret = secret
	config.MaxSessionAge = cfg.GetInt("MAX_SESSION_AGE")
	config.InsecureSkipVerify = cfg.GetBool("INSECURE_SKIP_VERIFY")

	return config, nil
}
