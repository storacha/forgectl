package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type ListProvidersResult struct {
	Providers []ProviderInfo `json:"providers"`
	HasMore   bool           `json:"hasMore"`
	Offset    int64          `json:"offset"`
	Limit     int64          `json:"limit"`
}

// ProviderInfo contains information about a service provider
type ProviderInfo struct {
	ID          uint64 `json:"id"`
	Address     string `json:"address"`
	Payee       string `json:"payee"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsActive    bool   `json:"isActive"`
	IsApproved  bool   `json:"isApproved"`
}

type ApprovalResult struct {
	TransactionHash common.Hash    `json:"transactionHash"`
	Receipt         *types.Receipt `json:"receipt"`
	ProviderID      uint64         `json:"providerId,omitempty"`
}

// PaymentStatus provides a comprehensive view of payment status for a payer
type PaymentStatus struct {
	CurrentEpoch     *big.Int       `json:"currentEpoch"`
	TokenAddress     common.Address `json:"tokenAddress"`
	Payer            *PayerStatus   `json:"payer"`
	Payees           []*PayeeStatus `json:"payees"`
	PricingRates     *PricingRates  `json:"pricingRates,omitempty"`
	MaxProvingPeriod uint64         `json:"maxProvingPeriod"` // proving period length from contract
}

// PricingRates contains current pricing information from the service contract
type PricingRates struct {
	StoragePrice *big.Int `json:"storagePrice"` // price per TiB/month in token base units
	MinimumRate  *big.Int `json:"minimumRate"`  // minimum rate per epoch
}

// PayerStatus contains the payer's account info, operator approval, and derived totals
type PayerStatus struct {
	Address          common.Address       `json:"address"`
	Account          *PaymentAccountInfo  `json:"account"`
	OperatorApproval *PaymentOperatorInfo `json:"operatorApproval"`
	// Derived values
	AvailableBalance *big.Int `json:"availableBalance"` // funds - lockupCurrent
	TotalUnsettled   *big.Int `json:"totalUnsettled"`   // sum across all rails
	TotalSettleable  *big.Int `json:"totalSettleable"`  // sum of settleable now
}

// PayeeStatus contains a payee's account info and all rails from the payer to this payee
type PayeeStatus struct {
	Address          common.Address      `json:"address"`
	Account          *PaymentAccountInfo `json:"account"`
	AvailableBalance *big.Int            `json:"availableBalance"` // what they can withdraw
	Rails            []*RailStatus       `json:"rails"`

	// Aggregated totals across all rails (using clear terminology)
	TotalOwed       *big.Int `json:"totalOwed"`       // total accrued since last settlement (was TotalUnsettled)
	TotalClaimable  *big.Int `json:"totalClaimable"`  // can settle now: funded + proven (was TotalActualSettleable)
	TotalUnfunded   *big.Int `json:"totalUnfunded"`   // payer hasn't locked funds yet (Owed - Theoretical)
	TotalProofFaults *big.Int `json:"totalProofFaults"` // lost due to missed proofs (Theoretical - Claimable)

	// Legacy fields for backwards compatibility (deprecated, use above)
	TotalUnsettled             *big.Int `json:"totalUnsettled"`             // same as TotalOwed
	TotalActualSettleable      *big.Int `json:"totalActualSettleable"`      // same as TotalClaimable
	TotalTheoreticalSettleable *big.Int `json:"totalTheoreticalSettleable"` // funded amount (Owed - Unfunded)

	// Rails grouped by dataset
	DataSets []*DataSetGroupStatus `json:"dataSets,omitempty"`
}

// RailStatus contains detailed information about a payment rail including calculated values
type RailStatus struct {
	RailId            *big.Int       `json:"railId"`
	PaymentRate       *big.Int       `json:"paymentRate"`
	SettledUpTo       *big.Int       `json:"settledUpTo"`
	LockupPeriod      *big.Int       `json:"lockupPeriod"`
	LockupFixed       *big.Int       `json:"lockupFixed"`
	IsTerminated      bool           `json:"isTerminated"`
	EndEpoch          *big.Int       `json:"endEpoch"`
	Operator          common.Address `json:"operator"`
	Validator         common.Address `json:"validator"`
	CommissionRateBps *big.Int       `json:"commissionRateBps"`

	// Dataset context
	DataSetId *big.Int `json:"dataSetId,omitempty"` // linked dataset ID (0 if none)
	RailType  string   `json:"railType,omitempty"`  // "PDP", "CDN", "CacheMiss", or "Unknown"

	// Derived - theoretical values (assuming 100% proofs)
	UnsettledEpochs  *big.Int `json:"unsettledEpochs"`  // theoretical total unsettled
	UnsettledAmount  *big.Int `json:"unsettledAmount"`  // unsettledEpochs × rate
	SettleableEpochs *big.Int `json:"settleableEpochs"` // what can be settled now (lockup cap)
	SettleableAmount *big.Int `json:"settleableAmount"` // settleableEpochs × rate (max if 100% proofs)

	// Derived - actual values (accounting for proof faults)
	ProvenEpochs     *big.Int `json:"provenEpochs"`     // epochs with successful proofs
	ActualSettleable *big.Int `json:"actualSettleable"` // provenEpochs × rate
	ProofSuccessRate float64  `json:"proofSuccessRate"` // provenEpochs / settleableEpochs
	HasValidator     bool     `json:"hasValidator"`     // false for CDN rails (no proof validation)

	// Lifetime proof tracking (since dataset activation)
	LifetimeProvenEpochs *big.Int `json:"lifetimeProvenEpochs,omitempty"` // total proven since activation
	LifetimeTotalEpochs  *big.Int `json:"lifetimeTotalEpochs,omitempty"`  // total epochs since activation
	LifetimeProofRate    float64  `json:"lifetimeProofRate,omitempty"`    // lifetime success rate
}

// DataSetInfo contains information about a dataset from the service contract
type DataSetInfo struct {
	DataSetId       *big.Int       `json:"dataSetId"`
	PdpRailId       *big.Int       `json:"pdpRailId"`
	CacheMissRailId *big.Int       `json:"cacheMissRailId"`
	CdnRailId       *big.Int       `json:"cdnRailId"`
	Payer           common.Address `json:"payer"`
	Payee           common.Address `json:"payee"`
	ServiceProvider common.Address `json:"serviceProvider"`
	CommissionBps   *big.Int       `json:"commissionBps"`
	ClientDataSetId *big.Int       `json:"clientDataSetId"`
	PdpEndEpoch     *big.Int       `json:"pdpEndEpoch"`
	ProviderId      *big.Int       `json:"providerId"`

	// Derived/computed values
	LeafCount   *big.Int `json:"leafCount"`   // from PDPVerifier.GetDataSetLeafCount
	SizeInBytes *big.Int `json:"sizeInBytes"` // computed from leafCount (leafCount * 32)
}

// DataSetGroupStatus groups rails belonging to the same dataset
type DataSetGroupStatus struct {
	DataSetInfo   *DataSetInfo `json:"dataSetInfo"`
	PdpRail       *RailStatus  `json:"pdpRail,omitempty"`
	CdnRail       *RailStatus  `json:"cdnRail,omitempty"`
	CacheMissRail *RailStatus  `json:"cacheMissRail,omitempty"`

	// Aggregated for this dataset
	TotalUnsettled      *big.Int `json:"totalUnsettled"`
	TotalSettleable     *big.Int `json:"totalSettleable"`
	TheoreticalEarnings *big.Int `json:"theoreticalEarnings"` // 100% proof success
	ActualEarnings      *big.Int `json:"actualEarnings"`      // proof-adjusted
}

type PaymentAccountInfo struct {
	Funds               *big.Int `json:"funds"`
	LockupCurrent       *big.Int `json:"lockupCurrent"`
	LockupRate          *big.Int `json:"lockupRate"`
	LockupLastSettledAt *big.Int `json:"lockupLastSettledAt"`
}

type PaymentOperatorInfo struct {
	IsApproved      bool     `json:"isApproved"`
	RateAllowance   *big.Int `json:"rateAllowance"`
	LockupAllowance *big.Int `json:"lockupAllowance"`
	RateUsage       *big.Int `json:"rateUsage"`
	LockupUsage     *big.Int `json:"lockupUsage"`
	MaxLockupPeriod *big.Int `json:"maxLockupPeriod"`
}

type ServiceContractPricing struct {
	PricePerTiBPerMonthNoCDN   *big.Int
	PricePerTiBCdnEgress       *big.Int
	PricePerTiBCacheMissEgress *big.Int
	TokenAddress               common.Address
	EpochsPerMonth             *big.Int
	MinimumPricePerMonth       *big.Int
}
