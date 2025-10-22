package inspector

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/forgectl/pkg/services/types"
	"golang.org/x/sync/errgroup"
)

func (s *Service) PaymentsStatus(ctx context.Context, tokenAddr, payer common.Address, offset, limit int64) (interface{}, error) {
	accountInfo, err := s.PaymentAccountInfo(ctx, tokenAddr, payer)
	if err != nil {
		return nil, err
	}
	operatorInfo, err := s.PaymentOperatorInfo(ctx, tokenAddr, payer)
	if err != nil {
		return nil, err
	}
	railsInfo, err := s.PaymentsRailsForPayer(ctx, tokenAddr, payer, offset, limit)
	if err != nil {
		return nil, err
	}

	grp, gctx := errgroup.WithContext(ctx)
	rails := make([]*types.PaymentsRailInfo, len(railsInfo.Rails))
	for i, r := range railsInfo.Rails {
		r := r
		i := i
		grp.Go(func() error {
			rail, err := s.PaymentsRailInfo(gctx, r.RailId)
			if err != nil {
				return err
			}
			rails[i] = rail
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return nil, err
	}

	return &types.PaymentStatus{
		AccountInfo:  accountInfo,
		OperatorInfo: operatorInfo,
		RailInfo:     railsInfo,
		Rails:        rails,
	}, nil
}

func (s *Service) PaymentAccountInfo(ctx context.Context, tokenAddr, payer common.Address) (*types.PaymentAccountInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	accountInfo, err := s.PaymentsContract.Accounts(bindCtx, tokenAddr, payer)
	if err != nil {
		return nil, fmt.Errorf("querying account information: %w", err)
	}

	return &types.PaymentAccountInfo{
		Funds:               accountInfo.Funds,
		LockupCurrent:       accountInfo.LockupCurrent,
		LockupRate:          accountInfo.LockupRate,
		LockupLastSettledAt: accountInfo.LockupLastSettledAt,
	}, nil
}

func (s *Service) PaymentOperatorInfo(ctx context.Context, tokenAddr, payer common.Address) (*types.PaymentOperatorInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	accountInfo, err := s.PaymentsContract.OperatorApprovals(bindCtx, tokenAddr, payer, s.ServiceAddr)
	if err != nil {
		return nil, fmt.Errorf("querying account information: %w", err)
	}

	return &types.PaymentOperatorInfo{
		IsApproved:      accountInfo.IsApproved,
		RateAllowance:   accountInfo.RateAllowance,
		LockupAllowance: accountInfo.LockupAllowance,
		RateUsage:       accountInfo.RateUsage,
		LockupUsage:     accountInfo.LockupUsage,
		MaxLockupPeriod: accountInfo.MaxLockupPeriod,
	}, nil
}

func (s *Service) PaymentsRailsForPayer(ctx context.Context, tokenAddr, payer common.Address, offset, limit int64) (*types.PaymentRailsInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	payerRails, err := s.PaymentsContract.GetRailsForPayerAndToken(bindCtx, payer, tokenAddr, big.NewInt(offset), big.NewInt(limit))
	if err != nil {
		return nil, fmt.Errorf("querying payment rails: %w", err)
	}

	railInfos := make([]types.PaymentRail, 0)
	for _, r := range payerRails.Results {
		railInfos = append(railInfos, types.PaymentRail{
			RailId:       r.RailId,
			IsTerminated: r.IsTerminated,
			EndEpoch:     r.EndEpoch,
		})
	}

	return &types.PaymentRailsInfo{
		Rails:      railInfos,
		NextOffset: payerRails.NextOffset,
		Total:      payerRails.Total,
	}, nil
}

func (s *Service) PaymentsRailInfo(ctx context.Context, railID *big.Int) (*types.PaymentsRailInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	railInfo, err := s.PaymentsContract.GetRail(bindCtx, railID)
	if err != nil {
		return nil, fmt.Errorf("querying payment rails: %w", err)
	}

	return &types.PaymentsRailInfo{
		Token:               railInfo.Token,
		From:                railInfo.From,
		To:                  railInfo.To,
		Operator:            railInfo.Operator,
		Validator:           railInfo.Validator,
		PaymentRate:         railInfo.PaymentRate,
		LockupPeriod:        railInfo.LockupPeriod,
		LockupFixed:         railInfo.LockupFixed,
		SettledUpTo:         railInfo.SettledUpTo,
		EndEpoch:            railInfo.EndEpoch,
		CommissionRateBps:   railInfo.CommissionRateBps,
		ServiceFeeRecipient: railInfo.ServiceFeeRecipient,
	}, nil
}
