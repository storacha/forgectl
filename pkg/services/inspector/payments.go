package inspector

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/sync/errgroup"

	"github.com/storacha/forgectl/pkg/services/types"
)

const (
	// ProvenPeriodsSlot is the storage slot for provenPeriods mapping in FilecoinWarmStorageService
	// From FilecoinWarmStorageServiceLayout.sol: PROVEN_PERIODS_SLOT = bytes32(uint256(3))
	ProvenPeriodsSlot = 3
)

// PaymentsStatus returns a comprehensive view of payment status for a payer,
// including all payees and their rails with calculated unsettled/settleable amounts.
func (s *Service) PaymentsStatus(ctx context.Context, tokenAddr, payer common.Address, offset, limit int64) (*types.PaymentStatus, error) {
	// 1. Parallel initial fetches: current block, payer account, operator info, pricing rates, max proving period
	var currentEpoch *big.Int
	var payerAccount *types.PaymentAccountInfo
	var operatorInfo *types.PaymentOperatorInfo
	var pricingRates *types.PricingRates
	var maxProvingPeriod uint64

	grpInit, gctxInit := errgroup.WithContext(ctx)

	grpInit.Go(func() error {
		currentBlock, err := s.client.BlockNumber(gctxInit)
		if err != nil {
			return fmt.Errorf("getting current block number: %w", err)
		}
		currentEpoch = new(big.Int).SetUint64(currentBlock)
		return nil
	})

	grpInit.Go(func() error {
		var err error
		payerAccount, err = s.PaymentAccountInfo(gctxInit, tokenAddr, payer)
		if err != nil {
			return fmt.Errorf("getting payer account info: %w", err)
		}
		return nil
	})

	grpInit.Go(func() error {
		var err error
		operatorInfo, err = s.PaymentOperatorInfo(gctxInit, tokenAddr, payer)
		if err != nil {
			return fmt.Errorf("getting operator info: %w", err)
		}
		return nil
	})

	grpInit.Go(func() error {
		var err error
		pricingRates, err = s.GetCurrentPricingRates(gctxInit)
		if err != nil {
			// Non-fatal - continue without pricing
			log.Warnw("failed to get pricing rates", "error", err)
		}
		return nil
	})

	grpInit.Go(func() error {
		bindCtx := &bind.CallOpts{Context: gctxInit}
		mpp, err := s.ServiceViewContract.GetMaxProvingPeriod(bindCtx)
		if err != nil {
			log.Warnw("failed to get max proving period", "error", err)
			maxProvingPeriod = 2880 // default fallback
		} else {
			maxProvingPeriod = mpp
		}
		return nil
	})

	if err := grpInit.Wait(); err != nil {
		return nil, err
	}

	// 2. Get all rails for payer (with pagination)
	bindCtx := &bind.CallOpts{Context: ctx}
	payerRails, err := s.PaymentsContract.GetRailsForPayerAndToken(bindCtx, payer, tokenAddr, big.NewInt(offset), big.NewInt(limit))
	if err != nil {
		return nil, fmt.Errorf("querying payment rails: %w", err)
	}

	// 3. Get detailed info for each rail and dataset IDs (parallel)
	type railInfo struct {
		railId       *big.Int
		isTerminated bool
		info         *railDetailInfo
		dataSetId    *big.Int
	}
	railDetails := make([]railInfo, len(payerRails.Results))

	grp, gctx := errgroup.WithContext(ctx)
	for i, r := range payerRails.Results {
		i, r := i, r
		grp.Go(func() error {
			detail, err := s.getRailDetailInfo(gctx, r.RailId)
			if err != nil {
				return err
			}

			// Also fetch dataset ID for this rail
			dataSetId, err := s.ServiceViewContract.RailToDataSet(&bind.CallOpts{Context: gctx}, r.RailId)
			if err != nil {
				log.Warnw("failed to get dataset for rail", "railId", r.RailId, "error", err)
				dataSetId = big.NewInt(0)
			}

			railDetails[i] = railInfo{
				railId:       r.RailId,
				isTerminated: r.IsTerminated,
				info:         detail,
				dataSetId:    dataSetId,
			}
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return nil, fmt.Errorf("getting rail details: %w", err)
	}

	// 4. Collect unique dataset IDs and fetch dataset infos + activation epochs in parallel
	uniqueDataSetIds := make(map[string]*big.Int)
	for _, rd := range railDetails {
		if rd.dataSetId != nil && rd.dataSetId.Sign() > 0 {
			uniqueDataSetIds[rd.dataSetId.String()] = rd.dataSetId
		}
	}

	dataSetInfos := make(map[string]*types.DataSetInfo)
	activationEpochs := make(map[string]*big.Int)
	var mu sync.Mutex
	grpDS, gctxDS := errgroup.WithContext(ctx)

	for _, dsId := range uniqueDataSetIds {
		dsId := dsId
		// Fetch dataset info
		grpDS.Go(func() error {
			info, err := s.GetDataSetInfo(gctxDS, dsId)
			if err != nil {
				log.Warnw("failed to get dataset info", "dataSetId", dsId, "error", err)
				return nil // non-fatal
			}
			mu.Lock()
			dataSetInfos[dsId.String()] = info
			mu.Unlock()
			return nil
		})
		// Fetch activation epoch for proving
		grpDS.Go(func() error {
			bindCtx := &bind.CallOpts{Context: gctxDS}
			activation, err := s.ServiceViewContract.ProvingActivationEpoch(bindCtx, dsId)
			if err != nil {
				log.Warnw("failed to get activation epoch", "dataSetId", dsId, "error", err)
				return nil // non-fatal
			}
			mu.Lock()
			activationEpochs[dsId.String()] = activation
			mu.Unlock()
			return nil
		})
	}
	grpDS.Wait() // ignore errors (non-fatal)

	// 5. Group rails by payee (To address)
	payeeRailsMap := make(map[common.Address][]railInfo)
	for _, rd := range railDetails {
		if rd.info == nil {
			continue
		}
		payeeRailsMap[rd.info.To] = append(payeeRailsMap[rd.info.To], rd)
	}

	// 6. Query each unique payee's account info (parallel)
	payeeAddrs := make([]common.Address, 0, len(payeeRailsMap))
	for addr := range payeeRailsMap {
		payeeAddrs = append(payeeAddrs, addr)
	}

	payeeAccounts := make(map[common.Address]*types.PaymentAccountInfo)
	var muPayee sync.Mutex
	grp2, gctx2 := errgroup.WithContext(ctx)
	for _, addr := range payeeAddrs {
		addr := addr
		grp2.Go(func() error {
			acct, err := s.PaymentAccountInfo(gctx2, tokenAddr, addr)
			if err != nil {
				return fmt.Errorf("getting payee %s account info: %w", addr.Hex(), err)
			}
			muPayee.Lock()
			payeeAccounts[addr] = acct
			muPayee.Unlock()
			return nil
		})
	}
	if err := grp2.Wait(); err != nil {
		return nil, err
	}

	// 7. Calculate derived values for each rail in parallel
	type railStatusResult struct {
		index  int
		status *types.RailStatus
	}

	// Flatten all rails for parallel processing
	type railJob struct {
		payeeAddr common.Address
		railIdx   int
		rd        railInfo
	}
	var allRailJobs []railJob
	for payeeAddr, rails := range payeeRailsMap {
		for i, rd := range rails {
			allRailJobs = append(allRailJobs, railJob{payeeAddr: payeeAddr, railIdx: i, rd: rd})
		}
	}

	// Calculate rail statuses in parallel
	railStatusResults := make(map[common.Address]map[int]*types.RailStatus)
	for addr := range payeeRailsMap {
		railStatusResults[addr] = make(map[int]*types.RailStatus)
	}
	var muRail sync.Mutex

	grpRail, gctxRail := errgroup.WithContext(ctx)
	for _, job := range allRailJobs {
		job := job
		grpRail.Go(func() error {
			// Get pre-fetched activation epoch for this dataset
			var activationEpoch *big.Int
			if job.rd.dataSetId != nil && job.rd.dataSetId.Sign() > 0 {
				activationEpoch = activationEpochs[job.rd.dataSetId.String()]
			}

			railStatus := s.calculateRailStatusFast(gctxRail, job.rd.info, job.rd.railId, job.rd.isTerminated,
				currentEpoch, payerAccount.LockupLastSettledAt, job.rd.dataSetId, activationEpoch, maxProvingPeriod)

			// Enrich with dataset info
			if job.rd.dataSetId != nil && job.rd.dataSetId.Sign() > 0 {
				railStatus.DataSetId = job.rd.dataSetId
				if dsInfo, ok := dataSetInfos[job.rd.dataSetId.String()]; ok {
					railStatus.RailType = determineRailType(job.rd.railId, dsInfo)
				} else {
					railStatus.RailType = "Unknown"
				}
			} else {
				railStatus.RailType = "Unknown"
			}

			muRail.Lock()
			railStatusResults[job.payeeAddr][job.railIdx] = railStatus
			muRail.Unlock()
			return nil
		})
	}
	grpRail.Wait() // errors logged internally

	// 8. Build payee statuses from parallel results
	totalUnsettled := big.NewInt(0)
	totalSettleable := big.NewInt(0)

	payees := make([]*types.PayeeStatus, 0, len(payeeAddrs))
	for _, payeeAddr := range payeeAddrs {
		rails := payeeRailsMap[payeeAddr]
		payeeAccount := payeeAccounts[payeeAddr]

		// Track payee totals
		payeeUnsettled := big.NewInt(0)
		payeeActualSettleable := big.NewInt(0)
		payeeTheoreticalSettleable := big.NewInt(0)

		// Map to group rails by dataset
		dataSetRailsMap := make(map[string][]*types.RailStatus)

		railStatuses := make([]*types.RailStatus, 0, len(rails))
		for i, rd := range rails {
			railStatus := railStatusResults[payeeAddr][i]
			if railStatus == nil {
				continue
			}

			if rd.dataSetId != nil && rd.dataSetId.Sign() > 0 {
				dataSetRailsMap[rd.dataSetId.String()] = append(dataSetRailsMap[rd.dataSetId.String()], railStatus)
			}

			railStatuses = append(railStatuses, railStatus)

			// Aggregate totals
			totalUnsettled = new(big.Int).Add(totalUnsettled, railStatus.UnsettledAmount)
			totalSettleable = new(big.Int).Add(totalSettleable, railStatus.SettleableAmount)

			// Payee totals
			payeeUnsettled = new(big.Int).Add(payeeUnsettled, railStatus.UnsettledAmount)
			if railStatus.ActualSettleable != nil {
				payeeActualSettleable = new(big.Int).Add(payeeActualSettleable, railStatus.ActualSettleable)
			}
			payeeTheoreticalSettleable = new(big.Int).Add(payeeTheoreticalSettleable, railStatus.SettleableAmount)
		}

		// Build dataset group statuses
		var dataSetGroups []*types.DataSetGroupStatus
		for dsIdStr, dsRails := range dataSetRailsMap {
			dsInfo := dataSetInfos[dsIdStr]
			if dsInfo == nil {
				continue
			}

			group := &types.DataSetGroupStatus{
				DataSetInfo:         dsInfo,
				TotalUnsettled:      big.NewInt(0),
				TotalSettleable:     big.NewInt(0),
				TheoreticalEarnings: big.NewInt(0),
				ActualEarnings:      big.NewInt(0),
			}

			for _, rail := range dsRails {
				// Assign to correct rail slot
				switch rail.RailType {
				case "PDP":
					group.PdpRail = rail
				case "CDN":
					group.CdnRail = rail
				case "CacheMiss":
					group.CacheMissRail = rail
				}

				// Aggregate
				group.TotalUnsettled = new(big.Int).Add(group.TotalUnsettled, rail.UnsettledAmount)
				group.TheoreticalEarnings = new(big.Int).Add(group.TheoreticalEarnings, rail.SettleableAmount)
				if rail.ActualSettleable != nil {
					group.ActualEarnings = new(big.Int).Add(group.ActualEarnings, rail.ActualSettleable)
					group.TotalSettleable = new(big.Int).Add(group.TotalSettleable, rail.ActualSettleable)
				} else {
					group.TotalSettleable = new(big.Int).Add(group.TotalSettleable, rail.SettleableAmount)
				}
			}

			dataSetGroups = append(dataSetGroups, group)
		}

		// Calculate payee's available balance
		payeeAvailable := new(big.Int).Sub(payeeAccount.Funds, payeeAccount.LockupCurrent)
		if payeeAvailable.Sign() < 0 {
			payeeAvailable = big.NewInt(0)
		}

		// Calculate unfunded and proof faults
		// Unfunded = Owed - Theoretical (payer hasn't locked funds)
		payeeUnfunded := new(big.Int).Sub(payeeUnsettled, payeeTheoreticalSettleable)
		if payeeUnfunded.Sign() < 0 {
			payeeUnfunded = big.NewInt(0)
		}
		// Proof Faults = Theoretical - Actual (missed proofs)
		payeeProofFaults := new(big.Int).Sub(payeeTheoreticalSettleable, payeeActualSettleable)
		if payeeProofFaults.Sign() < 0 {
			payeeProofFaults = big.NewInt(0)
		}

		payees = append(payees, &types.PayeeStatus{
			Address:          payeeAddr,
			Account:          payeeAccount,
			AvailableBalance: payeeAvailable,
			Rails:            railStatuses,
			// New clear terminology
			TotalOwed:        payeeUnsettled,
			TotalClaimable:   payeeActualSettleable,
			TotalUnfunded:    payeeUnfunded,
			TotalProofFaults: payeeProofFaults,
			// Legacy fields (for backwards compatibility)
			TotalUnsettled:             payeeUnsettled,
			TotalActualSettleable:      payeeActualSettleable,
			TotalTheoreticalSettleable: payeeTheoreticalSettleable,
			DataSets:                   dataSetGroups,
		})
	}

	// 8. Calculate payer's available balance
	payerAvailable := new(big.Int).Sub(payerAccount.Funds, payerAccount.LockupCurrent)
	if payerAvailable.Sign() < 0 {
		payerAvailable = big.NewInt(0)
	}

	return &types.PaymentStatus{
		CurrentEpoch: currentEpoch,
		TokenAddress: tokenAddr,
		Payer: &types.PayerStatus{
			Address:          payer,
			Account:          payerAccount,
			OperatorApproval: operatorInfo,
			AvailableBalance: payerAvailable,
			TotalUnsettled:   totalUnsettled,
			TotalSettleable:  totalSettleable,
		},
		Payees:           payees,
		PricingRates:     pricingRates,
		MaxProvingPeriod: maxProvingPeriod,
	}, nil
}

// railDetailInfo holds internal rail detail information
type railDetailInfo struct {
	Token               common.Address
	From                common.Address
	To                  common.Address
	Operator            common.Address
	Validator           common.Address
	PaymentRate         *big.Int
	LockupPeriod        *big.Int
	LockupFixed         *big.Int
	SettledUpTo         *big.Int
	EndEpoch            *big.Int
	CommissionRateBps   *big.Int
	ServiceFeeRecipient common.Address
}

// getRailDetailInfo fetches detailed information about a specific rail
func (s *Service) getRailDetailInfo(ctx context.Context, railID *big.Int) (*railDetailInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	railInfo, err := s.PaymentsContract.GetRail(bindCtx, railID)
	if err != nil {
		return nil, fmt.Errorf("querying rail %s: %w", railID, err)
	}

	return &railDetailInfo{
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

// calculateRailStatus computes the derived values for a rail including actual settleable amounts
func (s *Service) calculateRailStatus(ctx context.Context, rail *railDetailInfo, railId *big.Int, isTerminated bool, currentEpoch, lockupLastSettledAt *big.Int) *types.RailStatus {
	var unsettledEpochs, settleableEpochs *big.Int

	// Determine the settlement cap epoch
	var capEpoch *big.Int
	if isTerminated && rail.EndEpoch != nil && rail.EndEpoch.Cmp(big.NewInt(0)) > 0 {
		// Terminated rail - unsettled is up to endEpoch
		unsettledEpochs = new(big.Int).Sub(rail.EndEpoch, rail.SettledUpTo)
		// For terminated rails, streaming lockup covers all remaining epochs
		settleableEpochs = new(big.Int).Set(unsettledEpochs)
		capEpoch = rail.EndEpoch
	} else {
		// Non-terminated rail
		unsettledEpochs = new(big.Int).Sub(currentEpoch, rail.SettledUpTo)

		// Settleable is capped by lockupLastSettledAt
		capEpoch = new(big.Int).Set(currentEpoch)
		if lockupLastSettledAt.Cmp(currentEpoch) < 0 {
			capEpoch = lockupLastSettledAt
		}
		settleableEpochs = new(big.Int).Sub(capEpoch, rail.SettledUpTo)
	}

	// Clamp to zero if negative
	if unsettledEpochs.Sign() < 0 {
		unsettledEpochs = big.NewInt(0)
	}
	if settleableEpochs.Sign() < 0 {
		settleableEpochs = big.NewInt(0)
	}

	// Calculate theoretical amounts (assuming 100% proofs)
	unsettledAmount := new(big.Int).Mul(unsettledEpochs, rail.PaymentRate)
	settleableAmount := new(big.Int).Mul(settleableEpochs, rail.PaymentRate)

	// Determine if rail has a validator
	hasValidator := rail.Validator != (common.Address{})

	status := &types.RailStatus{
		RailId:            railId,
		PaymentRate:       rail.PaymentRate,
		SettledUpTo:       rail.SettledUpTo,
		LockupPeriod:      rail.LockupPeriod,
		LockupFixed:       rail.LockupFixed,
		IsTerminated:      isTerminated,
		EndEpoch:          rail.EndEpoch,
		Operator:          rail.Operator,
		Validator:         rail.Validator,
		CommissionRateBps: rail.CommissionRateBps,
		UnsettledEpochs:   unsettledEpochs,
		UnsettledAmount:   unsettledAmount,
		SettleableEpochs:  settleableEpochs,
		SettleableAmount:  settleableAmount,
		HasValidator:      hasValidator,
	}

	// If no validator, actual = theoretical (CDN rails pay fully)
	if !hasValidator {
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	// Query proving state
	provingState, err := s.getRailProvingState(ctx, railId)
	if err != nil {
		log.Warnw("failed to get proving state, falling back to theoretical", "railId", railId, "error", err)
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	if !provingState.HasValidator {
		// Rail not registered with service contract
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	// Count proven epochs
	provenEpochs, err := s.countProvenEpochs(ctx, provingState, rail.SettledUpTo, capEpoch)
	if err != nil {
		log.Warnw("failed to count proven epochs, falling back to theoretical", "railId", railId, "error", err)
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	// Cap by settleable (lockup constraint still applies)
	if provenEpochs.Cmp(settleableEpochs) > 0 {
		provenEpochs = new(big.Int).Set(settleableEpochs)
	}

	status.ProvenEpochs = provenEpochs
	status.ActualSettleable = new(big.Int).Mul(provenEpochs, rail.PaymentRate)

	// Calculate success rate
	if settleableEpochs.Sign() > 0 {
		provenF := new(big.Float).SetInt(provenEpochs)
		settleableF := new(big.Float).SetInt(settleableEpochs)
		rateF := new(big.Float).Quo(provenF, settleableF)
		status.ProofSuccessRate, _ = rateF.Float64()
	} else {
		status.ProofSuccessRate = 1.0
	}

	return status
}

// calculateRailStatusFast computes rail status using pre-fetched proving data (no extra RPC calls)
func (s *Service) calculateRailStatusFast(ctx context.Context, rail *railDetailInfo, railId *big.Int, isTerminated bool,
	currentEpoch, lockupLastSettledAt, dataSetId, activationEpoch *big.Int, maxProvingPeriod uint64) *types.RailStatus {

	var unsettledEpochs, settleableEpochs *big.Int

	// Determine the settlement cap epoch
	var capEpoch *big.Int
	if isTerminated && rail.EndEpoch != nil && rail.EndEpoch.Cmp(big.NewInt(0)) > 0 {
		unsettledEpochs = new(big.Int).Sub(rail.EndEpoch, rail.SettledUpTo)
		settleableEpochs = new(big.Int).Set(unsettledEpochs)
		capEpoch = rail.EndEpoch
	} else {
		unsettledEpochs = new(big.Int).Sub(currentEpoch, rail.SettledUpTo)
		capEpoch = new(big.Int).Set(currentEpoch)
		if lockupLastSettledAt.Cmp(currentEpoch) < 0 {
			capEpoch = lockupLastSettledAt
		}
		settleableEpochs = new(big.Int).Sub(capEpoch, rail.SettledUpTo)
	}

	if unsettledEpochs.Sign() < 0 {
		unsettledEpochs = big.NewInt(0)
	}
	if settleableEpochs.Sign() < 0 {
		settleableEpochs = big.NewInt(0)
	}

	unsettledAmount := new(big.Int).Mul(unsettledEpochs, rail.PaymentRate)
	settleableAmount := new(big.Int).Mul(settleableEpochs, rail.PaymentRate)
	hasValidator := rail.Validator != (common.Address{})

	status := &types.RailStatus{
		RailId:            railId,
		PaymentRate:       rail.PaymentRate,
		SettledUpTo:       rail.SettledUpTo,
		LockupPeriod:      rail.LockupPeriod,
		LockupFixed:       rail.LockupFixed,
		IsTerminated:      isTerminated,
		EndEpoch:          rail.EndEpoch,
		Operator:          rail.Operator,
		Validator:         rail.Validator,
		CommissionRateBps: rail.CommissionRateBps,
		UnsettledEpochs:   unsettledEpochs,
		UnsettledAmount:   unsettledAmount,
		SettleableEpochs:  settleableEpochs,
		SettleableAmount:  settleableAmount,
		HasValidator:      hasValidator,
	}

	// If no validator, actual = theoretical
	if !hasValidator {
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	// Check if we have proving data
	if dataSetId == nil || dataSetId.Sign() == 0 {
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	// Build proving state from pre-fetched data
	provingState := &railProvingState{
		DataSetId:        dataSetId,
		ActivationEpoch:  activationEpoch,
		MaxProvingPeriod: maxProvingPeriod,
		HasValidator:     true,
	}

	// Count proven epochs (this still fetches bitmaps, but they're small)
	provenEpochs, err := s.countProvenEpochs(ctx, provingState, rail.SettledUpTo, capEpoch)
	if err != nil {
		log.Warnw("failed to count proven epochs", "railId", railId, "error", err)
		status.ProvenEpochs = new(big.Int).Set(settleableEpochs)
		status.ActualSettleable = new(big.Int).Set(settleableAmount)
		status.ProofSuccessRate = 1.0
		return status
	}

	if provenEpochs.Cmp(settleableEpochs) > 0 {
		provenEpochs = new(big.Int).Set(settleableEpochs)
	}

	status.ProvenEpochs = provenEpochs
	status.ActualSettleable = new(big.Int).Mul(provenEpochs, rail.PaymentRate)

	if settleableEpochs.Sign() > 0 {
		provenF := new(big.Float).SetInt(provenEpochs)
		settleableF := new(big.Float).SetInt(settleableEpochs)
		rateF := new(big.Float).Quo(provenF, settleableF)
		status.ProofSuccessRate, _ = rateF.Float64()
	} else {
		status.ProofSuccessRate = 1.0
	}

	// Calculate lifetime proof rate (from activation to current/end epoch)
	// The bitmap is persistent, so we can query historical data
	if activationEpoch != nil && activationEpoch.Sign() > 0 {
		lifetimeEnd := currentEpoch
		if isTerminated && rail.EndEpoch != nil && rail.EndEpoch.Cmp(currentEpoch) < 0 {
			lifetimeEnd = rail.EndEpoch
		}
		lifetimeTotalEpochs := new(big.Int).Sub(lifetimeEnd, activationEpoch)
		if lifetimeTotalEpochs.Sign() > 0 {
			// Count proven epochs from activation to now
			lifetimeProven, err := s.countProvenEpochs(ctx, provingState,
				new(big.Int).Sub(activationEpoch, big.NewInt(1)), lifetimeEnd)
			if err == nil {
				status.LifetimeProvenEpochs = lifetimeProven
				status.LifetimeTotalEpochs = lifetimeTotalEpochs
				if lifetimeTotalEpochs.Sign() > 0 {
					provenF := new(big.Float).SetInt(lifetimeProven)
					totalF := new(big.Float).SetInt(lifetimeTotalEpochs)
					rate, _ := new(big.Float).Quo(provenF, totalF).Float64()
					status.LifetimeProofRate = rate
				}
			}
		}
	}

	return status
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

// railProvingState contains proving information for a specific rail
type railProvingState struct {
	DataSetId        *big.Int
	ActivationEpoch  *big.Int
	MaxProvingPeriod uint64
	HasValidator     bool // false if dataSetId == 0
}

// getRailProvingState fetches proving state for a rail
func (s *Service) getRailProvingState(ctx context.Context, railId *big.Int) (*railProvingState, error) {
	bindCtx := &bind.CallOpts{Context: ctx}

	// 1. railToDataSet(railId) -> dataSetId
	dataSetId, err := s.ServiceViewContract.RailToDataSet(bindCtx, railId)
	if err != nil {
		return nil, fmt.Errorf("querying rail to dataset mapping: %w", err)
	}

	// If dataSetId == 0, rail has no validator
	if dataSetId.Cmp(big.NewInt(0)) == 0 {
		return &railProvingState{HasValidator: false}, nil
	}

	// 2. provingActivationEpoch(dataSetId)
	activationEpoch, err := s.ServiceViewContract.ProvingActivationEpoch(bindCtx, dataSetId)
	if err != nil {
		return nil, fmt.Errorf("querying proving activation epoch: %w", err)
	}

	// 3. getMaxProvingPeriod()
	maxProvingPeriod, err := s.ServiceViewContract.GetMaxProvingPeriod(bindCtx)
	if err != nil {
		return nil, fmt.Errorf("querying max proving period: %w", err)
	}

	return &railProvingState{
		DataSetId:        dataSetId,
		ActivationEpoch:  activationEpoch,
		MaxProvingPeriod: maxProvingPeriod,
		HasValidator:     true,
	}, nil
}

// calculateProvenPeriodsSlot computes storage slot for provenPeriods[dataSetId][bucketId]
// Formula: keccak256(bucketId . keccak256(dataSetId . baseSlot))
func calculateProvenPeriodsSlot(dataSetId *big.Int, bucketId uint64) [32]byte {
	baseSlot := common.LeftPadBytes(big.NewInt(ProvenPeriodsSlot).Bytes(), 32)
	dataSetIdBytes := common.LeftPadBytes(dataSetId.Bytes(), 32)

	// Inner: keccak256(dataSetId . baseSlot)
	innerData := append(dataSetIdBytes, baseSlot...)
	innerHash := crypto.Keccak256(innerData)

	// Outer: keccak256(bucketId . innerHash)
	bucketIdBytes := common.LeftPadBytes(big.NewInt(int64(bucketId)).Bytes(), 32)
	outerData := append(bucketIdBytes, innerHash...)

	var slot [32]byte
	copy(slot[:], crypto.Keccak256(outerData))
	return slot
}

// getProvenPeriodsBitmap fetches raw bitmap via extsload
func (s *Service) getProvenPeriodsBitmap(ctx context.Context, dataSetId *big.Int, bucketId uint64) (*big.Int, error) {
	slot := calculateProvenPeriodsSlot(dataSetId, bucketId)
	bindCtx := &bind.CallOpts{Context: ctx}
	result, err := s.ServiceContract.Extsload(bindCtx, slot)
	if err != nil {
		return nil, fmt.Errorf("reading storage slot via extsload: %w", err)
	}
	return new(big.Int).SetBytes(result[:]), nil
}

// countProvenEpochs counts proven epochs in range [fromEpoch+1, toEpoch]
// This mirrors the contract's _findProvenEpochs logic.
// Epochs before proving activation are counted as proven (no proofs required).
func (s *Service) countProvenEpochs(
	ctx context.Context,
	state *railProvingState,
	fromEpoch *big.Int, // settledUpTo (exclusive start)
	toEpoch *big.Int,   // currentEpoch (inclusive end)
) (*big.Int, error) {
	fromEpochU := fromEpoch.Uint64()
	toEpochU := toEpoch.Uint64()

	// Nothing to count if range is empty
	if toEpochU <= fromEpochU {
		return big.NewInt(0), nil
	}

	totalEpochs := toEpochU - fromEpochU

	// If no validator or proving not activated, all epochs are proven (no proofs required)
	if !state.HasValidator || state.ActivationEpoch == nil || state.ActivationEpoch.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(int64(totalEpochs)), nil
	}

	activationEpoch := state.ActivationEpoch.Uint64()
	maxPeriod := state.MaxProvingPeriod

	// Count epochs before activation as proven (no proofs required for these)
	var provenBeforeActivation uint64
	adjustedFrom := fromEpochU
	if fromEpochU+1 < activationEpoch {
		// Epochs from fromEpoch+1 to min(activationEpoch-1, toEpoch) don't require proofs
		proofFreeEnd := activationEpoch - 1
		if toEpochU < proofFreeEnd {
			proofFreeEnd = toEpochU
		}
		provenBeforeActivation = proofFreeEnd - fromEpochU
		adjustedFrom = activationEpoch - 1
	}

	// If all epochs are before activation, they're all proven
	if toEpochU <= activationEpoch {
		return big.NewInt(int64(provenBeforeActivation)), nil
	}

	// Calculate period range
	startPeriod := epochToPeriod(adjustedFrom+1, activationEpoch, maxPeriod)
	endPeriod := epochToPeriod(toEpochU, activationEpoch, maxPeriod)

	// Calculate bucket range (each bucket holds 256 periods)
	startBucket := startPeriod >> 8
	endBucket := endPeriod >> 8

	// Fetch all needed bitmaps (typically 1-2 calls)
	bitmaps := make(map[uint64]*big.Int)
	for bucket := startBucket; bucket <= endBucket; bucket++ {
		bitmap, err := s.getProvenPeriodsBitmap(ctx, state.DataSetId, bucket)
		if err != nil {
			return nil, fmt.Errorf("fetching bitmap for bucket %d: %w", bucket, err)
		}
		bitmaps[bucket] = bitmap
	}

	// Count proven epochs (mirrors _findProvenEpochs in contract)
	var provenCount uint64

	startPeriodDeadline := activationEpoch + (startPeriod+1)*maxPeriod

	if toEpochU < startPeriodDeadline {
		// All epochs within single period
		if isPeriodProven(bitmaps, startPeriod) {
			provenCount = toEpochU - adjustedFrom
		}
		return big.NewInt(int64(provenBeforeActivation + provenCount)), nil
	}

	// First period (partial)
	if isPeriodProven(bitmaps, startPeriod) {
		provenCount += startPeriodDeadline - adjustedFrom - 1
	}

	// Middle periods (full)
	for period := startPeriod + 1; period < endPeriod; period++ {
		if isPeriodProven(bitmaps, period) {
			provenCount += maxPeriod
		}
	}

	// Last period (partial)
	if endPeriod > startPeriod {
		lastPeriodStart := activationEpoch + endPeriod*maxPeriod
		if isPeriodProven(bitmaps, endPeriod) {
			provenCount += toEpochU - lastPeriodStart
		}
	}

	return big.NewInt(int64(provenBeforeActivation + provenCount)), nil
}

func epochToPeriod(epoch, activationEpoch, maxPeriod uint64) uint64 {
	if epoch < activationEpoch {
		return 0
	}
	return (epoch - activationEpoch) / maxPeriod
}

func isPeriodProven(bitmaps map[uint64]*big.Int, periodId uint64) bool {
	bucketId := periodId >> 8
	bitIndex := periodId & 255

	bitmap, ok := bitmaps[bucketId]
	if !ok || bitmap == nil {
		return false
	}

	// Check bit: (bitmap >> bitIndex) & 1
	return bitmap.Bit(int(bitIndex)) == 1
}

// GetCurrentPricingRates fetches the current storage pricing rates from the service contract
func (s *Service) GetCurrentPricingRates(ctx context.Context) (*types.PricingRates, error) {
	bindCtx := &bind.CallOpts{Context: ctx}
	rates, err := s.ServiceViewContract.GetCurrentPricingRates(bindCtx)
	if err != nil {
		return nil, fmt.Errorf("querying pricing rates: %w", err)
	}
	return &types.PricingRates{
		StoragePrice: rates.StoragePrice,
		MinimumRate:  rates.MinimumRate,
	}, nil
}

// GetDataSetInfo fetches comprehensive dataset information including size
func (s *Service) GetDataSetInfo(ctx context.Context, dataSetId *big.Int) (*types.DataSetInfo, error) {
	bindCtx := &bind.CallOpts{Context: ctx}

	// Fetch dataset info from service view contract
	info, err := s.ServiceViewContract.GetDataSet(bindCtx, dataSetId)
	if err != nil {
		return nil, fmt.Errorf("querying dataset %s: %w", dataSetId, err)
	}

	// Fetch leaf count from PDPVerifier contract
	leafCount := big.NewInt(0)
	if s.PDPVerifierContract != nil {
		lc, err := s.PDPVerifierContract.GetDataSetLeafCount(bindCtx, dataSetId)
		if err != nil {
			// Non-fatal: dataset may not have leaf count yet
			log.Warnw("failed to get leaf count", "dataSetId", dataSetId, "error", err)
		} else {
			leafCount = lc
		}
	}

	// Calculate size in bytes (leafCount * 32)
	sizeInBytes := new(big.Int).Mul(leafCount, big.NewInt(32))

	return &types.DataSetInfo{
		DataSetId:       dataSetId,
		PdpRailId:       info.PdpRailId,
		CacheMissRailId: info.CacheMissRailId,
		CdnRailId:       info.CdnRailId,
		Payer:           info.Payer,
		Payee:           info.Payee,
		ServiceProvider: info.ServiceProvider,
		CommissionBps:   info.CommissionBps,
		ClientDataSetId: info.ClientDataSetId,
		PdpEndEpoch:     info.PdpEndEpoch,
		ProviderId:      info.ProviderId,
		LeafCount:       leafCount,
		SizeInBytes:     sizeInBytes,
	}, nil
}

// determineRailType determines the rail type based on dataset info
func determineRailType(railId *big.Int, dataSetInfo *types.DataSetInfo) string {
	if dataSetInfo == nil || railId == nil {
		return "Unknown"
	}
	if dataSetInfo.PdpRailId != nil && railId.Cmp(dataSetInfo.PdpRailId) == 0 {
		return "PDP"
	}
	if dataSetInfo.CdnRailId != nil && railId.Cmp(dataSetInfo.CdnRailId) == 0 {
		return "CDN"
	}
	if dataSetInfo.CacheMissRailId != nil && railId.Cmp(dataSetInfo.CacheMissRailId) == 0 {
		return "CacheMiss"
	}
	return "Unknown"
}
