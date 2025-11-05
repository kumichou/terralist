package saml

import (
	"fmt"
	"strings"

	"terralist/pkg/auth"
)

type Creator struct{}

func (c *Creator) New(config auth.Configurator) (auth.Provider, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("unsupported configurator")
	}

	// Build ACS URL from Terralist base URL
	acsURL := strings.TrimSuffix(cfg.TerralistSchemeHostAndPort, "/") + "/v1/api/auth/saml/acs"

	return &Provider{
		IdPMetadataURL:             cfg.IdPMetadataURL,
		IdPMetadataFile:            cfg.IdPMetadataFile,
		SPEntityID:                 cfg.SPEntityID,
		SPMetadataURL:              cfg.SPMetadataURL,
		ACSUrl:                     acsURL,
		NameAttribute:              cfg.NameAttribute,
		EmailAttribute:             cfg.EmailAttribute,
		GroupsAttribute:            cfg.GroupsAttribute,
		CertFile:                   cfg.CertFile,
		KeyFile:                    cfg.KeyFile,
		TerralistSchemeHostAndPort: cfg.TerralistSchemeHostAndPort,
	}, nil
}
