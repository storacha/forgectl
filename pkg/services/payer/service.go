package payer

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
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

// AuthorizeSessionParams contains parameters for authorizing a session key
type AuthorizeSessionParams struct {
	Address     common.Address
	Expiry      *big.Int
	Permissions [][32]byte
	Origin      string
}

// AuthorizeSession authorizes a session key address with the given expiry and permissions
// by calling the SessionKeyRegistry contract's Login method
func (s *Service) AuthorizeSession(ctx context.Context, params AuthorizeSessionParams) (*ethtypes.Receipt, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.SessionKeyRegistryContract.Login(
			s.tx.Auth(ctx),
			params.Address,
			params.Expiry,
			params.Permissions,
			params.Origin,
		)
	}, "authorizing session key")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}

// SetOperatorApprovalParams contains parameters for setting operator approval
type SetOperatorApprovalParams struct {
	Approve         bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	MaxLockupPeriod *big.Int
}

// SetOperatorApproval approves the service operator using the Payments contract's
// setOperatorApproval method. Uses the TokenAddr and ServiceAddr from the inspector.
func (s *Service) SetOperatorApproval(ctx context.Context, params SetOperatorApprovalParams) (*ethtypes.Receipt, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.PaymentsContract.SetOperatorApproval(
			s.tx.Auth(ctx),
			s.TokenAddr,
			s.ServiceAddr,
			params.Approve,
			params.RateAllowance,
			params.LockupAllowance,
			params.MaxLockupPeriod,
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
