package google

import (
	"fmt"

	"terralist/pkg/auth"
)

type Creator struct{}

func (c *Creator) New(config auth.Configurator) (auth.Provider, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("unsupported configurator")
	}

	return &Provider{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Domain:       cfg.Domain,
	}, nil
}
