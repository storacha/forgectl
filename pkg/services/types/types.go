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

type PaymentStatus struct {
	AccountInfo  *PaymentAccountInfo
	OperatorInfo *PaymentOperatorInfo
	RailInfo     *PaymentRailsInfo
	Rails        []*PaymentsRailInfo
}

type PaymentAccountInfo struct {
	Funds               *big.Int
	LockupCurrent       *big.Int
	LockupRate          *big.Int
	LockupLastSettledAt *big.Int
}

type PaymentOperatorInfo struct {
	IsApproved      bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	RateUsage       *big.Int
	LockupUsage     *big.Int
	MaxLockupPeriod *big.Int
}

type PaymentRailsInfo struct {
	Rails      []PaymentRail
	NextOffset *big.Int
	Total      *big.Int
}

type PaymentRail struct {
	RailId       *big.Int
	IsTerminated bool
	EndEpoch     *big.Int
}

type PaymentsRailInfo struct {
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

type ServiceContractPricing struct {
	PricePerTiBPerMonthNoCDN   *big.Int
	PricePerTiBPerMonthWithCDN *big.Int
	TokenAddress               common.Address
	EpochsPerMonth             *big.Int
}
