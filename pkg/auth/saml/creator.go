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
	metadataURL := strings.TrimSuffix(cfg.TerralistSchemeHostAndPort, "/") + "/v1/api/auth/saml/metadata"

	return &Provider{
		IdPMetadataURL:             cfg.IdPMetadataURL,
		IdPMetadataFile:            cfg.IdPMetadataFile,
		IdPEntityID:                cfg.IdPEntityID,
		IdPSSOURL:                  cfg.IdPSSOURL,
		IdPSSOCertificate:          cfg.IdPSSOCertificate,
		SPEntityID:                 metadataURL, // SP Entity ID is the metadata URL
		ACSUrl:                     acsURL,
		MetadataURL:                metadataURL,
		NameAttribute:              cfg.NameAttribute,
		EmailAttribute:             cfg.EmailAttribute,
		GroupsAttribute:            cfg.GroupsAttribute,
		CertFile:                   cfg.CertFile,
		KeyFile:                    cfg.KeyFile,
		PrivateKeySecret:           cfg.PrivateKeySecret,
		TerralistSchemeHostAndPort: cfg.TerralistSchemeHostAndPort,
		requestTracker:             newRequestTracker(cfg.RequestIDCleanupInterval),
		stopMetadataRefresh:        make(chan struct{}),
	}, nil
}
