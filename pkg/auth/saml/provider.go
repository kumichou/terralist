package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"terralist/pkg/auth"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Provider is the concrete implementation of auth.Provider for SAML authentication.
type Provider struct {
	IdPMetadataURL             string
	IdPMetadataFile            string
	SPEntityID                 string
	SPMetadataURL              string
	ACSUrl                     string
	NameAttribute              string
	EmailAttribute             string
	GroupsAttribute            string
	CertFile                   string
	KeyFile                    string
	TerralistSchemeHostAndPort string

	// Internal state: SAML components
	idpMetadata     *saml.EntityDescriptor
	spCertificate   *x509.Certificate
	spPrivateKey    *rsa.PrivateKey
	serviceProvider *saml.ServiceProvider
}

var (
	httpClient = &http.Client{}
)

func (p *Provider) Name() string {
	return "SAML"
}

// GetAuthorizeUrl initiates the SAML SSO flow by creating a SAML AuthnRequest
// and redirecting to the IdP's SSO endpoint.
// The state parameter is used to maintain the OAuth flow state for Terraform compatibility.
func (p *Provider) GetAuthorizeUrl(state string) string {
	// Ensure IdP metadata is loaded
	if p.idpMetadata == nil {
		if err := p.loadIdPMetadata(); err != nil {
			// Return error URL - this will be handled by the caller
			return fmt.Sprintf("%s?error=metadata_load_failed&error_description=%s", p.ACSUrl, url.QueryEscape(err.Error()))
		}
	}

	// Ensure service provider is initialized
	if p.serviceProvider == nil {
		if err := p.initializeServiceProvider(); err != nil {
			return fmt.Sprintf("%s?error=sp_init_failed&error_description=%s", p.ACSUrl, url.QueryEscape(err.Error()))
		}
	}

	// Get SSO URL from IdP metadata
	idpSSOURL := p.getSSOURL()
	if idpSSOURL == "" {
		return fmt.Sprintf("%s?error=no_sso_url&error_description=%s", p.ACSUrl, url.QueryEscape("no SSO URL found in IdP metadata"))
	}

	// Create SAML AuthnRequest using the library
	authnRequest, err := p.serviceProvider.MakeAuthenticationRequest(
		idpSSOURL,
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return fmt.Sprintf("%s?error=authn_request_failed&error_description=%s", p.ACSUrl, url.QueryEscape(err.Error()))
	}

	// Get the redirect URL with SAMLRequest and RelayState (state)
	redirectURL, err := authnRequest.Redirect(state, p.serviceProvider)
	if err != nil {
		return fmt.Sprintf("%s?error=redirect_failed&error_description=%s", p.ACSUrl, url.QueryEscape(err.Error()))
	}

	return redirectURL.String()
}

// GetUserDetails parses the SAMLResponse (provided as base64 encoded XML in the code parameter)
// and extracts user attributes to populate the user struct.
func (p *Provider) GetUserDetails(samlResponse string, user *auth.User) error {
	// Decode base64 SAMLResponse
	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Ensure service provider is initialized for response validation
	if p.serviceProvider == nil {
		if err := p.initializeServiceProvider(); err != nil {
			return fmt.Errorf("failed to initialize service provider: %w", err)
		}
	}

	// Parse ACS URL for validation
	acsURL, err := url.Parse(p.ACSUrl)
	if err != nil {
		return fmt.Errorf("invalid ACS URL: %w", err)
	}

	// Parse and validate SAML Response using the library
	// Note: possibleRequestIDs is empty for now since we're not tracking request IDs
	// In production, you should track request IDs for security
	assertion, err := p.serviceProvider.ParseXMLResponse(samlResponseXML, nil, *acsURL)
	if err != nil {
		return fmt.Errorf("failed to parse/validate SAML response: %w", err)
	}

	// Extract attributes from the assertion
	attributes := make(map[string][]string)
	if len(assertion.AttributeStatements) > 0 {
		attrStatement := assertion.AttributeStatements[0]
		for _, attr := range attrStatement.Attributes {
			// Get the attribute name (handle both Name and FriendlyName)
			attrName := attr.Name
			if attrName == "" {
				attrName = attr.FriendlyName
			}

			// Extract attribute values
			var values []string
			for _, val := range attr.Values {
				values = append(values, val.Value)
			}
			attributes[attrName] = values
		}
	}

	// Map attributes to user struct
	if err := p.mapAttributesToUser(attributes, user); err != nil {
		return fmt.Errorf("failed to map attributes: %w", err)
	}

	return nil
}

// loadIdPMetadata loads and parses the IdP metadata from URL or file using the crewjam/saml library.
func (p *Provider) loadIdPMetadata() error {
	if p.IdPMetadataURL != "" {
		// Fetch from URL using the library
		metadataURL, err := url.Parse(p.IdPMetadataURL)
		if err != nil {
			return fmt.Errorf("invalid IdP metadata URL: %w", err)
		}

		metadata, err := samlsp.FetchMetadata(context.Background(), httpClient, *metadataURL)
		if err != nil {
			return fmt.Errorf("failed to fetch IdP metadata from URL: %w", err)
		}

		p.idpMetadata = metadata
	} else if p.IdPMetadataFile != "" {
		// Read from file
		file, err := os.Open(p.IdPMetadataFile)
		if err != nil {
			return fmt.Errorf("failed to open IdP metadata file: %w", err)
		}
		defer file.Close()

		// Parse metadata XML using xml.Decoder
		metadata := &saml.EntityDescriptor{}
		if err := xml.NewDecoder(file).Decode(metadata); err != nil {
			return fmt.Errorf("failed to parse IdP metadata: %w", err)
		}

		p.idpMetadata = metadata
	} else {
		return fmt.Errorf("no IdP metadata source provided")
	}

	if p.idpMetadata == nil {
		return fmt.Errorf("failed to load IdP metadata")
	}

	return nil
}

// initializeServiceProvider initializes the SAML Service Provider using the library.
func (p *Provider) initializeServiceProvider() error {
	// Load SP certificate and key if provided
	if p.CertFile != "" && p.KeyFile != "" {
		keyPair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate/key pair: %w", err)
		}

		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		p.spCertificate = keyPair.Leaf

		privateKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not an RSA key")
		}
		p.spPrivateKey = privateKey
	} else {
		// Generate a self-signed certificate if not provided
		// This is for development/testing - production should use proper certificates
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: p.SPEntityID,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		p.spCertificate = cert
		p.spPrivateKey = privateKey
	}

	// Parse ACS URL
	acsURL, err := url.Parse(p.ACSUrl)
	if err != nil {
		return fmt.Errorf("invalid ACS URL: %w", err)
	}

	// Get metadata URL
	metadataURL := p.getMetadataURL()

	// Create service provider
	sp := &saml.ServiceProvider{
		EntityID:          p.SPEntityID,
		Key:               p.spPrivateKey,
		Certificate:       p.spCertificate,
		IDPMetadata:       p.idpMetadata,
		AcsURL:            *acsURL,
		MetadataURL:       *metadataURL,
		AllowIDPInitiated: false,
	}

	p.serviceProvider = sp

	return nil
}

// getSSOURL returns the SSO URL from the IdP metadata.
func (p *Provider) getSSOURL() string {
	if p.idpMetadata == nil {
		return ""
	}

	if len(p.idpMetadata.IDPSSODescriptors) > 0 {
		idpSSODescriptor := p.idpMetadata.IDPSSODescriptors[0]
		for _, ssoService := range idpSSODescriptor.SingleSignOnServices {
			if ssoService.Binding == saml.HTTPRedirectBinding {
				return ssoService.Location
			}
		}
		// Fallback to first SSO service if redirect binding not found
		if len(idpSSODescriptor.SingleSignOnServices) > 0 {
			return idpSSODescriptor.SingleSignOnServices[0].Location
		}
	}

	return ""
}

// getMetadataURL returns the SP metadata URL if configured.
func (p *Provider) getMetadataURL() *url.URL {
	if p.SPMetadataURL != "" {
		metadataURL, err := url.Parse(p.SPMetadataURL)
		if err == nil {
			return metadataURL
		}
	}

	// Default to root URL + /saml/metadata
	rootURL, err := url.Parse(p.TerralistSchemeHostAndPort)
	if err == nil {
		metadataURL := *rootURL
		metadataURL.Path = "/saml/metadata"
		return &metadataURL
	}

	// Fallback to ACS URL base
	acsURL, err := url.Parse(p.ACSUrl)
	if err == nil {
		metadataURL := *acsURL
		metadataURL.Path = "/saml/metadata"
		return &metadataURL
	}

	// Last resort: return a default
	defaultURL, _ := url.Parse("http://localhost/saml/metadata")
	return defaultURL
}

// mapAttributesToUser maps SAML attributes to the user struct.
func (p *Provider) mapAttributesToUser(attributes map[string][]string, user *auth.User) error {
	// Extract name
	if nameAttr, ok := attributes[p.NameAttribute]; ok && len(nameAttr) > 0 {
		user.Name = nameAttr[0]
	} else {
		// Try common SAML attribute names
		for _, attrName := range []string{"displayName", "name", "givenName", "cn", "uid"} {
			if nameAttr, ok := attributes[attrName]; ok && len(nameAttr) > 0 {
				user.Name = nameAttr[0]
				break
			}
		}
	}

	if user.Name == "" {
		return fmt.Errorf("name attribute not found in SAML response")
	}

	// Extract email
	if emailAttr, ok := attributes[p.EmailAttribute]; ok && len(emailAttr) > 0 {
		user.Email = emailAttr[0]
	} else {
		// Try common SAML attribute names
		for _, attrName := range []string{"email", "mail", "emailAddress"} {
			if emailAttr, ok := attributes[attrName]; ok && len(emailAttr) > 0 {
				user.Email = emailAttr[0]
				break
			}
		}
	}

	if user.Email == "" {
		return fmt.Errorf("email attribute not found in SAML response")
	}

	// Extract groups (optional)
	if p.GroupsAttribute != "" {
		if groupsAttr, ok := attributes[p.GroupsAttribute]; ok {
			user.Groups = groupsAttr
		}
	}

	return nil
}
