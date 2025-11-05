package saml

import (
	"fmt"
)

// Config implements auth.Configurator interface and
// handles the configuration parameters for SAML authentication.
type Config struct {
	// IdPMetadataURL is the URL where the IdP metadata can be fetched from.
	// Either IdPMetadataURL or IdPMetadataFile must be provided.
	IdPMetadataURL string

	// IdPMetadataFile is the local file path to the IdP metadata XML file.
	// Either IdPMetadataURL or IdPMetadataFile must be provided.
	IdPMetadataFile string

	// SPEntityID is the Service Provider entity ID, used to identify this SP to the IdP.
	// This is required.
	SPEntityID string

	// SPMetadataURL is the URL where the SP metadata can be fetched by the IdP.
	// This is optional but recommended for IdP configuration.
	SPMetadataURL string

	// NameAttribute is the SAML attribute name that contains the user's name.
	// Defaults to common SAML attribute names if not specified.
	NameAttribute string

	// EmailAttribute is the SAML attribute name that contains the user's email.
	// Defaults to common SAML attribute names if not specified.
	EmailAttribute string

	// GroupsAttribute is the SAML attribute name that contains the user's groups.
	// This is optional and used for RBAC group mapping.
	GroupsAttribute string

	// CertFile is the path to the certificate file (PEM format) used for signing SAML requests.
	// This is optional but recommended for production deployments.
	CertFile string

	// KeyFile is the path to the private key file (PEM format) used for signing SAML requests.
	// This is optional but recommended for production deployments.
	KeyFile string

	// TerralistSchemeHostAndPort is the base URL of the Terralist instance.
	// Used to construct the ACS (Assertion Consumer Service) redirect URL.
	TerralistSchemeHostAndPort string
}

func (c *Config) SetDefaults() {
	if c.NameAttribute == "" {
		c.NameAttribute = "displayName"
	}

	if c.EmailAttribute == "" {
		c.EmailAttribute = "email"
	}
}

func (c *Config) Validate() error {
	if c.IdPMetadataURL == "" && c.IdPMetadataFile == "" {
		return fmt.Errorf("missing required IdP metadata: either IdPMetadataURL or IdPMetadataFile must be provided")
	}

	if c.IdPMetadataURL != "" && c.IdPMetadataFile != "" {
		return fmt.Errorf("both IdPMetadataURL and IdPMetadataFile cannot be set at the same time")
	}

	if c.SPEntityID == "" {
		return fmt.Errorf("missing required SP entity ID")
	}

	if c.TerralistSchemeHostAndPort == "" {
		return fmt.Errorf("missing required Terralist scheme host and port")
	}

	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("cert file specified but key file is missing")
	}

	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("key file specified but cert file is missing")
	}

	return nil
}
