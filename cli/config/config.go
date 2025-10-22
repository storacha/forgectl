package config

import (
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/viper"
)

// Load reads configuration from viper and returns a validated Config struct.
// It reads from configuration file, environment variables, and command-line flags
// in that order of precedence (flags override env vars which override config file).
func Load() (*Config, error) {
	var cfg Config

	// Use viper's Unmarshal to populate the Config struct with proper mapstructure tags
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

type Config struct {
	// Network configuration
	RPCUrl string `mapstructure:"rpc_url"`

	// Contract addresses
	ServiceContractAddress         string `mapstructure:"service_contract_address"`          // FilecoinWarmStorageService (Proxy)
	VerifierContractAddress        string `mapstructure:"verifier_contract_address"`         // PDPVerifier (Proxy)
	ServiceRegistryContractAddress string `mapstructure:"service_registry_contract_address"` // ServiceProviderRegistry (Proxy)
	PaymentsContractAddress        string `mapstructure:"payments_contract_address"`         // Payments Contract
	TokenContractAddress           string `mapstructure:"token_contract_address"`            // USDFC Token

	KeystorePath     string `mapstructure:"keystore_path"`
	KeystorePassword string `mapstructure:"keystore_password"`
}

// Validate checks that all required configuration fields are set and valid
func (c *Config) Validate() error {
	// Validate RPC URL
	if c.RPCUrl == "" {
		return fmt.Errorf("rpc_url is required")
	}
	if _, err := url.Parse(c.RPCUrl); err != nil {
		return fmt.Errorf("invalid rpc_url: %w", err)
	}

	// Validate contract addresses
	if c.ServiceContractAddress == "" {
		return fmt.Errorf("service_contract_address is required")
	}
	if !common.IsHexAddress(c.ServiceContractAddress) {
		return fmt.Errorf("invalid service_contract_address: %s", c.ServiceContractAddress)
	}

	if c.VerifierContractAddress == "" {
		return fmt.Errorf("verifier_contract_address is required")
	}
	if !common.IsHexAddress(c.VerifierContractAddress) {
		return fmt.Errorf("invalid verifier_contract_address: %s", c.VerifierContractAddress)
	}

	if c.ServiceRegistryContractAddress == "" {
		return fmt.Errorf("service_registry_contract_address is required")
	}
	if !common.IsHexAddress(c.ServiceRegistryContractAddress) {
		return fmt.Errorf("invalid service_registry_contract_address: %s", c.ServiceRegistryContractAddress)
	}

	if c.PaymentsContractAddress == "" {
		return fmt.Errorf("payments_contract_address is required")
	}
	if !common.IsHexAddress(c.PaymentsContractAddress) {
		return fmt.Errorf("invalid payments_contract_address: %s", c.PaymentsContractAddress)
	}

	if c.TokenContractAddress == "" {
		return fmt.Errorf("token_contract_address is required")
	}
	if !common.IsHexAddress(c.TokenContractAddress) {
		return fmt.Errorf("invalid token_contract_address: %s", c.TokenContractAddress)
	}

	if c.KeystorePath == "" {
		return fmt.Errorf("keystore_path is required")
	}
	if c.KeystorePassword == "" {
		return fmt.Errorf("keystore_password is required")
	}

	return nil
}

// ServiceAddr returns the service contract address as a common.Address
func (c *Config) ServiceAddr() common.Address {
	return common.HexToAddress(c.ServiceContractAddress)
}

// VerifierAddr returns the verifier contract address as a common.Address
func (c *Config) VerifierAddr() common.Address {
	return common.HexToAddress(c.VerifierContractAddress)
}

// ServiceRegistryAddr returns the service registry contract address as a common.Address
func (c *Config) ServiceRegistryAddr() common.Address {
	return common.HexToAddress(c.ServiceRegistryContractAddress)
}

// PaymentsAddr returns the payments contract address as a common.Address
func (c *Config) PaymentsAddr() common.Address {
	return common.HexToAddress(c.PaymentsContractAddress)
}

// TokenAddr returns the token contract address as a common.Address
func (c *Config) TokenAddr() common.Address {
	return common.HexToAddress(c.TokenContractAddress)
}
