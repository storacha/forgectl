package inspector

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/forgectl/pkg/services/types"
)

// ListProviders queries all registered service providers
func (s *Service) ListProviders(ctx context.Context, offset, limit int64) (*types.ListProvidersResult, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	providers, err := s.RegistryContract.GetAllActiveProviders(bindCtx, big.NewInt(offset), big.NewInt(limit))
	if err != nil {
		return nil, fmt.Errorf("getting all providers failed: %v", err)
	}

	if len(providers.ProviderIds) == 0 {
		// nobody here...
		return &types.ListProvidersResult{
			Providers: make([]types.ProviderInfo, 0),
			HasMore:   false,
			Offset:    offset,
			Limit:     limit,
		}, nil
	}

	// Get full provider information
	providerInfos, err := s.RegistryContract.GetProvidersByIds(bindCtx, providers.ProviderIds)
	if err != nil {
		return nil, fmt.Errorf("getting provider details: %w", err)
	}

	// Convert to display format
	result := make([]types.ProviderInfo, 0, len(providerInfos.ProviderInfos))
	for idx, providerView := range providerInfos.ProviderInfos {
		if !providerInfos.ValidIds[idx] {
			continue
		}

		var isApproved bool
		approved, err := s.ServiceViewContract.IsProviderApproved(bindCtx, providerView.ProviderId)
		if err != nil {
			log.Warnw("failed to check if provider is approved", "id", providerView.ProviderId.Uint64(), "error", err)
			isApproved = false
		} else {
			isApproved = approved
		}

		result = append(result, types.ProviderInfo{
			ID:          providerView.ProviderId.Uint64(),
			Address:     providerView.Info.ServiceProvider.Hex(),
			Payee:       providerView.Info.Payee.Hex(),
			Name:        providerView.Info.Name,
			Description: providerView.Info.Description,
			IsActive:    providerView.Info.IsActive,
			IsApproved:  isApproved,
		})
	}

	return &types.ListProvidersResult{
		Providers: result,
		HasMore:   providers.HasMore,
		Offset:    offset,
		Limit:     limit,
	}, nil
}

func (s *Service) GetProviderByID(ctx context.Context, id uint64) (*types.ProviderInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	provider, err := s.RegistryContract.GetProvider(bindCtx, big.NewInt(int64(id)))
	if err != nil {
		return nil, fmt.Errorf("getting provider by id %d: %w", id, err)
	}
	var isApproved bool
	approved, err := s.ServiceViewContract.IsProviderApproved(bindCtx, provider.ProviderId)
	if err != nil {
		log.Warnw("failed to check if provider is approved", "id", provider.ProviderId.Uint64(), "error", err)
		isApproved = false
	} else {
		isApproved = approved
	}
	return &types.ProviderInfo{
		ID:          provider.ProviderId.Uint64(),
		Address:     provider.Info.ServiceProvider.String(),
		Payee:       provider.Info.Payee.String(),
		Name:        provider.Info.Name,
		Description: provider.Info.Description,
		IsActive:    provider.Info.IsActive,
		IsApproved:  isApproved,
	}, nil
}

func (s *Service) GetProviderByAddress(ctx context.Context, addr common.Address) (*types.ProviderInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	provider, err := s.RegistryContract.GetProviderByAddress(bindCtx, addr)
	if err != nil {
		return nil, fmt.Errorf("getting provider by address %s: %w", addr, err)
	}
	var isApproved bool
	approved, err := s.ServiceViewContract.IsProviderApproved(bindCtx, provider.ProviderId)
	if err != nil {
		log.Warnw("failed to check if provider is approved", "id", provider.ProviderId.Uint64(), "error", err)
		isApproved = false
	} else {
		isApproved = approved
	}
	return &types.ProviderInfo{
		ID:          provider.ProviderId.Uint64(),
		Address:     provider.Info.ServiceProvider.String(),
		Payee:       provider.Info.Payee.String(),
		Name:        provider.Info.Name,
		Description: provider.Info.Description,
		IsActive:    provider.Info.IsActive,
		IsApproved:  isApproved,
	}, nil
}
