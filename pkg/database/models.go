package database

import (
	"database/sql/driver"
	"fmt"
	"math/big"
	"time"
)

// ============================================================================
// Entity Models (Reference Data)
// ============================================================================

// Payer represents an account being monitored
type Payer struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Address   string    `gorm:"type:varchar(42);uniqueIndex" json:"address"`
	CreatedAt time.Time `gorm:"not null" json:"createdAt"`
}

// TableName overrides the table name
func (Payer) TableName() string {
	return "payers"
}

// Token represents an ERC20 token contract
type Token struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	Address   string    `gorm:"type:varchar(42);uniqueIndex" json:"address"`
	Symbol    string    `gorm:"type:varchar(20)" json:"symbol"`
	Decimals  int       `json:"decimals"`
	CreatedAt time.Time `gorm:"not null" json:"createdAt"`
}

// TableName overrides the table name
func (Token) TableName() string {
	return "tokens"
}

// Provider represents a service provider from ListProviders
type Provider struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	Address     string    `gorm:"type:varchar(42);uniqueIndex" json:"address"`
	ProviderID  BigInt    `gorm:"type:numeric;uniqueIndex" json:"providerId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Payee       string    `gorm:"type:varchar(42)" json:"payee"`
	CreatedAt   time.Time `gorm:"not null" json:"createdAt"`
}

// TableName overrides the table name
func (Provider) TableName() string {
	return "providers"
}

// Contract represents a smart contract (validator, operator, fee recipient)
type Contract struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	Address      string    `gorm:"type:varchar(42);uniqueIndex" json:"address"`
	ContractType string    `gorm:"type:varchar(50)" json:"contractType"`
	CreatedAt    time.Time `gorm:"not null" json:"createdAt"`
}

// TableName overrides the table name
func (Contract) TableName() string {
	return "contracts"
}

// PayerTokenPair represents the scope of monitoring (payer + token combination)
type PayerTokenPair struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	PayerID   uint      `gorm:"not null;uniqueIndex:idx_payer_token_unique" json:"payerId"`
	TokenID   uint      `gorm:"not null;uniqueIndex:idx_payer_token_unique" json:"tokenId"`
	CreatedAt time.Time `gorm:"not null" json:"createdAt"`
}

// TableName overrides the table name
func (PayerTokenPair) TableName() string {
	return "payer_token_pairs"
}

// ============================================================================
// BigInt Type
// ============================================================================

// BigInt is a wrapper around big.Int that implements sql.Scanner and driver.Valuer
// for proper PostgreSQL numeric type handling
type BigInt struct {
	*big.Int
}

// NewBigInt creates a new BigInt from a big.Int pointer
func NewBigInt(i *big.Int) BigInt {
	if i == nil {
		return BigInt{big.NewInt(0)}
	}
	return BigInt{i}
}

// Scan implements sql.Scanner for reading from database
func (b *BigInt) Scan(value interface{}) error {
	if value == nil {
		b.Int = big.NewInt(0)
		return nil
	}

	switch v := value.(type) {
	case int64:
		b.Int = big.NewInt(v)
	case []byte:
		b.Int = new(big.Int)
		if _, ok := b.Int.SetString(string(v), 10); !ok {
			return fmt.Errorf("failed to parse big.Int from bytes: %s", string(v))
		}
	case string:
		b.Int = new(big.Int)
		if _, ok := b.Int.SetString(v, 10); !ok {
			return fmt.Errorf("failed to parse big.Int from string: %s", v)
		}
	default:
		return fmt.Errorf("unsupported type for BigInt: %T", value)
	}
	return nil
}

// Value implements driver.Valuer for writing to database
func (b BigInt) Value() (driver.Value, error) {
	if b.Int == nil {
		return "0", nil
	}
	return b.Int.String(), nil
}

// ============================================================================
// Time-Series Models (with triggers)
// ============================================================================

// PaymentAccountSnapshot represents a historical snapshot of payment account information
type PaymentAccountSnapshot struct {
	ID                  uint      `gorm:"primarykey" json:"id"`
	PayerTokenPairID    uint      `gorm:"not null;index:idx_ptp_checked" json:"payerTokenPairId"`
	Funds               BigInt    `gorm:"type:numeric" json:"funds"`
	LockupCurrent       BigInt    `gorm:"type:numeric" json:"lockupCurrent"`
	LockupRate          BigInt    `gorm:"type:numeric" json:"lockupRate"`
	LockupLastSettledAt BigInt    `gorm:"type:numeric" json:"lockupLastSettledAt"`
	CreatedAt           time.Time `gorm:"not null" json:"createdAt"`        // When this state was first observed
	CheckedAt           time.Time `gorm:"index:idx_ptp_checked" json:"checkedAt"` // When this state was last verified
}

// TableName overrides the table name
func (PaymentAccountSnapshot) TableName() string {
	return "payment_account_snapshots"
}

// PaymentOperatorSnapshot represents a historical snapshot of payment operator information
type PaymentOperatorSnapshot struct {
	ID               uint      `gorm:"primarykey" json:"id"`
	PayerTokenPairID uint      `gorm:"not null;index:idx_ptp_checked" json:"payerTokenPairId"`
	IsApproved       bool      `json:"isApproved"`
	RateAllowance    BigInt    `gorm:"type:numeric" json:"rateAllowance"`
	LockupAllowance  BigInt    `gorm:"type:numeric" json:"lockupAllowance"`
	RateUsage        BigInt    `gorm:"type:numeric" json:"rateUsage"`
	LockupUsage      BigInt    `gorm:"type:numeric" json:"lockupUsage"`
	MaxLockupPeriod  BigInt    `gorm:"type:numeric" json:"maxLockupPeriod"`
	CreatedAt        time.Time `gorm:"not null" json:"createdAt"`             // When this state was first observed
	CheckedAt        time.Time `gorm:"index:idx_ptp_checked" json:"checkedAt"` // When this state was last verified
}

// TableName overrides the table name
func (PaymentOperatorSnapshot) TableName() string {
	return "payment_operator_snapshots"
}

// PaymentRailsSummary represents the summary of payment rails for a payer
type PaymentRailsSummary struct {
	ID               uint      `gorm:"primarykey" json:"id"`
	PayerTokenPairID uint      `gorm:"not null;index:idx_ptp_checked" json:"payerTokenPairId"`
	TotalRails       BigInt    `gorm:"type:numeric" json:"totalRails"`
	NextOffset       BigInt    `gorm:"type:numeric" json:"nextOffset"`
	CreatedAt        time.Time `gorm:"not null" json:"createdAt"`             // When this state was first observed
	CheckedAt        time.Time `gorm:"index:idx_ptp_checked" json:"checkedAt"` // When this state was last verified
}

// TableName overrides the table name
func (PaymentRailsSummary) TableName() string {
	return "payment_rails_summary"
}

// PaymentRailInfo represents detailed information about a payment rail
type PaymentRailInfo struct {
	ID                            uint      `gorm:"primarykey" json:"id"`
	RailID                        BigInt    `gorm:"type:numeric;uniqueIndex" json:"railId"`
	PayerTokenPairID              uint      `gorm:"not null;index:idx_ptp_checked" json:"payerTokenPairId"`
	ProviderID                    uint      `gorm:"not null" json:"providerId"`
	OperatorContractID            uint      `gorm:"not null" json:"operatorContractId"`
	ValidatorContractID           uint      `gorm:"not null" json:"validatorContractId"`
	ServiceFeeRecipientContractID uint      `gorm:"not null" json:"serviceFeeRecipientContractId"`
	PaymentRate                   BigInt    `gorm:"type:numeric" json:"paymentRate"`
	LockupPeriod                  BigInt    `gorm:"type:numeric" json:"lockupPeriod"`
	LockupFixed                   BigInt    `gorm:"type:numeric" json:"lockupFixed"`
	SettledUpTo                   BigInt    `gorm:"type:numeric" json:"settledUpTo"`
	EndEpoch                      BigInt    `gorm:"type:numeric" json:"endEpoch"`
	CommissionRateBps             BigInt    `gorm:"type:numeric" json:"commissionRateBps"`
	IsTerminated                  bool      `json:"isTerminated"`
	CreatedAt                     time.Time `gorm:"not null" json:"createdAt"`             // When this state was first observed
	CheckedAt                     time.Time `gorm:"index:idx_rail_checked" json:"checkedAt"` // When this state was last verified
}

// TableName overrides the table name
func (PaymentRailInfo) TableName() string {
	return "payment_rail_info"
}

// ProviderSnapshot represents a historical snapshot of provider state
type ProviderSnapshot struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	ProviderID uint      `gorm:"not null;index:idx_provider_checked" json:"providerId"`
	IsActive   bool      `json:"isActive"`
	IsApproved bool      `json:"isApproved"`
	CreatedAt  time.Time `gorm:"not null" json:"createdAt"`             // When this state was first observed
	CheckedAt  time.Time `gorm:"index:idx_provider_checked" json:"checkedAt"` // When this state was last verified
}

// TableName overrides the table name
func (ProviderSnapshot) TableName() string {
	return "provider_snapshots"
}

// ============================================================================
// Constructor Functions
// ============================================================================

// NewPaymentAccountSnapshot creates a new snapshot from payment account info
func NewPaymentAccountSnapshot(payerTokenPairID uint, funds, lockupCurrent, lockupRate, lockupLastSettledAt *big.Int) *PaymentAccountSnapshot {
	now := time.Now()
	return &PaymentAccountSnapshot{
		PayerTokenPairID:    payerTokenPairID,
		Funds:               NewBigInt(funds),
		LockupCurrent:       NewBigInt(lockupCurrent),
		LockupRate:          NewBigInt(lockupRate),
		LockupLastSettledAt: NewBigInt(lockupLastSettledAt),
		CreatedAt:           now,
		CheckedAt:           now,
	}
}

// NewPaymentOperatorSnapshot creates a new snapshot from payment operator info
func NewPaymentOperatorSnapshot(payerTokenPairID uint, isApproved bool, rateAllowance, lockupAllowance, rateUsage, lockupUsage, maxLockupPeriod *big.Int) *PaymentOperatorSnapshot {
	now := time.Now()
	return &PaymentOperatorSnapshot{
		PayerTokenPairID: payerTokenPairID,
		IsApproved:       isApproved,
		RateAllowance:    NewBigInt(rateAllowance),
		LockupAllowance:  NewBigInt(lockupAllowance),
		RateUsage:        NewBigInt(rateUsage),
		LockupUsage:      NewBigInt(lockupUsage),
		MaxLockupPeriod:  NewBigInt(maxLockupPeriod),
		CreatedAt:        now,
		CheckedAt:        now,
	}
}

// NewPaymentRailsSummary creates a new rails summary from inspector data
func NewPaymentRailsSummary(payerTokenPairID uint, totalRails, nextOffset *big.Int) *PaymentRailsSummary {
	now := time.Now()
	return &PaymentRailsSummary{
		PayerTokenPairID: payerTokenPairID,
		TotalRails:       NewBigInt(totalRails),
		NextOffset:       NewBigInt(nextOffset),
		CreatedAt:        now,
		CheckedAt:        now,
	}
}

// NewPaymentRailInfo creates a new rail info from inspector data
func NewPaymentRailInfo(railID *big.Int, payerTokenPairID, providerID, operatorContractID, validatorContractID, serviceFeeRecipientContractID uint,
	paymentRate, lockupPeriod, lockupFixed, settledUpTo, endEpoch, commissionRateBps *big.Int, isTerminated bool) *PaymentRailInfo {
	now := time.Now()
	return &PaymentRailInfo{
		RailID:                        NewBigInt(railID),
		PayerTokenPairID:              payerTokenPairID,
		ProviderID:                    providerID,
		OperatorContractID:            operatorContractID,
		ValidatorContractID:           validatorContractID,
		ServiceFeeRecipientContractID: serviceFeeRecipientContractID,
		PaymentRate:                   NewBigInt(paymentRate),
		LockupPeriod:                  NewBigInt(lockupPeriod),
		LockupFixed:                   NewBigInt(lockupFixed),
		SettledUpTo:                   NewBigInt(settledUpTo),
		EndEpoch:                      NewBigInt(endEpoch),
		CommissionRateBps:             NewBigInt(commissionRateBps),
		IsTerminated:                  isTerminated,
		CreatedAt:                     now,
		CheckedAt:                     now,
	}
}

// NewProviderSnapshot creates a new provider snapshot
func NewProviderSnapshot(providerID uint, isActive, isApproved bool) *ProviderSnapshot {
	now := time.Now()
	return &ProviderSnapshot{
		ProviderID: providerID,
		IsActive:   isActive,
		IsApproved: isApproved,
		CreatedAt:  now,
		CheckedAt:  now,
	}
}
