package inspector

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/forgectl/pkg/services/types"
)

// QueryServicePrice queries the service contract for pricing information
// This includes the price per TiB per month, token address, and epochs per month
func (s *Service) QueryServicePrice(ctx context.Context) (*types.ServiceContractPricing, error) {
	// Call getServicePrice
	pricing, err := s.ServiceContract.GetServicePrice(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("calling getServicePrice: %w", err)
	}

	return &types.ServiceContractPricing{
		PricePerTiBPerMonthNoCDN:   pricing.PricePerTiBPerMonthNoCDN,
		PricePerTiBPerMonthWithCDN: pricing.PricePerTiBPerMonthWithCDN,
		TokenAddress:               pricing.TokenAddress,
		EpochsPerMonth:             pricing.EpochsPerMonth,
	}, nil
}

const (
	// ERC20DecimalsSelector is the method selector for ERC20.decimals()
	// This is the first 4 bytes of Keccak256("decimals()") = 0x313ce567...
	ERC20DecimalsSelector = "0x313ce567"
)

func (s *Service) QueryTokenDecimals(ctx context.Context, tokenAddress common.Address) (uint8, error) {
	// Call the decimals() method using a simple contract call
	data := common.FromHex(ERC20DecimalsSelector)

	msg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: data,
	}

	result, err := s.Client().CallContract(ctx, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("calling decimals(): %w", err)
	}

	if len(result) != 32 {
		return 0, fmt.Errorf("unexpected result length: got %d, expected 32", len(result))
	}

	// The result is a uint8 encoded as bytes32 (right-padded)
	// We need to extract the last byte
	decimals := result[31]

	return decimals, nil
}
