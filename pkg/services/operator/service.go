package operator

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/services/types"
)

type Service struct {
	*inspector.Service
	tx *chain.Transactor
}

func New(inspector *inspector.Service, transactor *chain.Transactor) (*Service, error) {
	return &Service{
		Service: inspector,
		tx:      transactor,
	}, nil
}

// ApproveProvider approves a provider to create datasets (uses 'owner' role)
func (s *Service) ApproveProvider(ctx context.Context, providerID uint64) (*types.ApprovalResult, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.ServiceContract.AddApprovedProvider(s.tx.Auth(ctx), big.NewInt(int64(providerID)))
	}, "approving provider")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	approvedID, err := chain.GetProviderApprovedEvent(receipt)
	if err != nil {
		return nil, fmt.Errorf("getting provider approved event: %w", err)
	}

	return &types.ApprovalResult{
		TransactionHash: tx.Hash(),
		Receipt:         receipt,
		ProviderID:      approvedID.Uint64(),
	}, nil
}

type SetOperatorApprovalParams struct {
	TokenAddress    common.Address
	OperatorAddress common.Address
	Approve         bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	LockupPeriod    *big.Int
}

func (s *Service) SetOperatorApproval(ctx context.Context, params SetOperatorApprovalParams) (*ethtypes.Receipt, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.PaymentsContract.SetOperatorApproval(
			s.tx.Auth(ctx),
			params.TokenAddress,
			params.OperatorAddress,
			params.Approve,
			params.RateAllowance,
			params.LockupAllowance,
			params.LockupPeriod,
		)
	}, "setting operator approval")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}
