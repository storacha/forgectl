package inspector

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	logging "github.com/ipfs/go-log/v2"
	"github.com/storacha/filecoin-services/go/bindings"
)

var log = logging.Logger("service/inspector")

type Service struct {
	client *ethclient.Client

	PaymentsContract    *bindings.Payments
	PaymentContractAddr common.Address

	ServiceViewContract *bindings.FilecoinWarmStorageServiceStateView
	ServiceViewAddr     common.Address

	ServiceContract *bindings.FilecoinWarmStorageService
	ServiceAddr     common.Address

	RegistryContract *bindings.ServiceProviderRegistry
	RegistryAddr     common.Address

	TokenAddr common.Address

	SessionKeyRegistryContract *bindings.SessionKeyRegistry
	SessionKeyRegistryAddr     common.Address
}

type Config struct {
	// required
	ClientEndpoint            string
	PaymentsContractAddress   common.Address
	ServiceContractAddress    common.Address
	ProviderRegistryAddress   common.Address
	SessionKeyRegistryAddress common.Address
	TokenAddress              common.Address

	// optional, can derive from service contract
	serviceContractViewAddress common.Address
}

type Option func(*Config) error

func WithServiceViewAddress(addr common.Address) Option {
	return func(c *Config) error {
		if addr == (common.Address{}) {
			return fmt.Errorf("service view address caonnot be empty")
		}
		c.ServiceContractAddress = addr
		return nil
	}
}

func New(cfg Config, opts ...Option) (*Service, error) {
	for _, o := range opts {
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}
	// Connect to Ethereum client
	ethClient, err := ethclient.Dial(cfg.ClientEndpoint)
	if err != nil {
		return nil, fmt.Errorf("connecting to RPC endpoint: %w", err)
	}

	// Create contract bindings
	paymentsContract, err := bindings.NewPayments(cfg.PaymentsContractAddress, ethClient)
	if err != nil {
		return nil, fmt.Errorf("creating payments contract binding: %w", err)
	}

	serviceContract, err := bindings.NewFilecoinWarmStorageService(cfg.ServiceContractAddress, ethClient)
	if err != nil {
		return nil, fmt.Errorf("creating service contract binding: %w", err)
	}

	registryContract, err := bindings.NewServiceProviderRegistry(cfg.ProviderRegistryAddress, ethClient)
	if err != nil {
		return nil, fmt.Errorf("creating registry contract binding: %w", err)
	}

	sessionKeyRegistryContract, err := bindings.NewSessionKeyRegistry(cfg.SessionKeyRegistryAddress, ethClient)
	if err != nil {
		return nil, fmt.Errorf("creating session key registry contract binding: %w", err)
	}
	viewAddr := cfg.serviceContractViewAddress
	if viewAddr == (common.Address{}) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var err error
		viewAddr, err = serviceContract.ViewContractAddress(&bind.CallOpts{Context: ctx})
		if err != nil {
			return nil, fmt.Errorf("retrieving service view contract address: %w", err)
		}
	}

	serviceContractView, err := bindings.NewFilecoinWarmStorageServiceStateView(viewAddr, ethClient)
	if err != nil {
		return nil, fmt.Errorf("creating service contract view binding: %w", err)
	}

	return &Service{
		client:              ethClient,
		PaymentsContract:    paymentsContract,
		PaymentContractAddr: cfg.PaymentsContractAddress,

		ServiceViewContract: serviceContractView,
		ServiceViewAddr:     viewAddr,

		ServiceContract: serviceContract,
		ServiceAddr:     cfg.ServiceContractAddress,

		RegistryContract: registryContract,
		RegistryAddr:     cfg.ProviderRegistryAddress,

		SessionKeyRegistryContract: sessionKeyRegistryContract,
		SessionKeyRegistryAddr:     cfg.SessionKeyRegistryAddress,

		TokenAddr: cfg.TokenAddress,
	}, nil
}

func (s *Service) Client() *ethclient.Client {
	return s.client
}

func (s *Service) ChainID(ctx context.Context) (*big.Int, error) {
	return s.client.ChainID(ctx)
}
