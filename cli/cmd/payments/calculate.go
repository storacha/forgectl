// TODO: THIS NEEDS REVIEW ON MATHS
package payments

import (
	"fmt"
	"math/big"

	"github.com/dustin/go-humanize"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/inspector"

	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
)

const (
	EpochsPerDay   = 2_880
	EpochsPerMonth = EpochsPerDay * 30
	TiBInBytes     = 1_099_511_627_776 // 1024^4

	DefaultLockupDays          = 10
	DefaultMaxLockupPeriodDays = 30
)

var (
	calcLockupDays          int
	calcMaxLockupPeriodDays int
)

// AllowanceCalculation holds the calculated allowance values
type AllowanceCalculation struct {
	// Input parameters
	SizeInBytes         *big.Int
	LockupDays          int
	MaxLockupPeriodDays int

	// Calculated values
	RateAllowance   *big.Int // tokens per epoch
	LockupAllowance *big.Int // total tokens
	MaxLockupPeriod *big.Int // in epochs

	// Intermediate values for display
	LockupPeriodEpochs int64
	RatePerEpoch       *big.Int
}

var calculateCmd = &cobra.Command{
	Use:   "calculate [SIZE]",
	Short: "Calculate operator approval allowances from dataset size",
	Args:  cobra.ExactArgs(1),
	Long: `Calculate the rate allowance, lockup allowance, and max lockup period values
Formula:
  rateAllowance = (sizeInBytes × price) / (1TiB × 86,400 epochs)
  lockupAllowance = rateAllowance × (lockupDays × 2,880 epochs/day)
  maxLockupPeriod = maxLockupPeriodDays × 2,880 epochs/day
`,
	RunE: runCalculate,
}

func init() {
	calculateCmd.Flags().IntVar(&calcLockupDays, "lockup-days", DefaultLockupDays, "Lockup period in days")
	calculateCmd.Flags().IntVar(&calcMaxLockupPeriodDays, "max-lockup-period-days", DefaultMaxLockupPeriodDays, "Maximum lockup period in days")
}

func runCalculate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Parse size
	sizeInBytes, err := ParseSize(args[0])
	if err != nil {
		return err
	}

	is, err := inspector.New(inspector.Config{
		ClientEndpoint:          cfg.RPCUrl,
		PaymentsContractAddress: cfg.PaymentsAddr(),
		ServiceContractAddress:  cfg.ServiceAddr(),
		ProviderRegistryAddress: cfg.ServiceRegistryAddr(),
	})
	if err != nil {
		return err
	}

	// TODO the pricing ep can problalby get the token decimals
	pricing, err := is.QueryServicePrice(ctx)
	if err != nil {
		return err
	}

	// NB: if you want a human readable number for pricing in $ then you'll need this
	/*
		tokenDecimals, err := is.QueryTokenDecimals(ctx, cfg.TokenAddr())
		if err != nil {
			return err
		}
	*/

	// Calculate allowances
	calc, err := CalculateAllowances(sizeInBytes, calcLockupDays, calcMaxLockupPeriodDays, pricing.PricePerTiBPerMonthNoCDN, EpochsPerMonth)
	if err != nil {
		return fmt.Errorf("calculating allowances: %w", err)
	}

	return printer.AsJson(cmd.OutOrStdout(), calc)
}

// ParseSize parses human-readable size strings like "1TiB", "500GiB", "1.5TiB" to bytes
// Uses go-humanize to parse sizes (supports TB, GB, MB, KB or TiB, GiB, MiB, KiB)
func ParseSize(sizeStr string) (*big.Int, error) {
	bytes, err := humanize.ParseBytes(sizeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid size format: %s (expected format: 1TiB, 500GiB, 1.5TiB): %w", sizeStr, err)
	}

	result := new(big.Int)
	result.SetUint64(bytes)

	return result, nil
}

// CalculateAllowances calculates the rate allowance, lockup allowance, and max lockup period
// based on the dataset size and lockup parameters.
//
// Formula from https://filecoinproject.slack.com/archives/C07CGTXHHT4/p1759276539956319
//   rateAllowance = (sizeInBytes × pricePerTiBPerMonth) / (TiB_IN_BYTES × epochsPerMonth)
//   lockupAllowance = ratePerEpoch × lockupPeriodInEpochs
//   maxLockupPeriod = maxLockupPeriodDays × EpochsPerDay
//
// Parameters:
//   - sizeInBytes: The dataset size in bytes
//   - lockupDays: The lockup period in days
//   - maxLockupPeriodDays: The maximum lockup period in days
//   - pricePerTiBPerMonth: The price per TiB per month in base token units (queried from contract)
//   - epochsPerMonth: The number of epochs per month (queried from contract)
func CalculateAllowances(sizeInBytes *big.Int, lockupDays int, maxLockupPeriodDays int, pricePerTiBPerMonth *big.Int, epochsPerMonth uint64) (*AllowanceCalculation, error) {
	if sizeInBytes == nil || sizeInBytes.Sign() <= 0 {
		return nil, fmt.Errorf("size must be greater than 0")
	}
	if lockupDays <= 0 {
		return nil, fmt.Errorf("lockup days must be greater than 0")
	}
	if maxLockupPeriodDays <= 0 {
		return nil, fmt.Errorf("max lockup period days must be greater than 0")
	}
	if pricePerTiBPerMonth == nil || pricePerTiBPerMonth.Sign() <= 0 {
		return nil, fmt.Errorf("price per TiB per month must be greater than 0")
	}
	if epochsPerMonth == 0 {
		return nil, fmt.Errorf("epochs per month must be greater than 0")
	}

	// Calculate rate per epoch
	// rateAllowance = (sizeInBytes × pricePerTiBPerMonth) / (TiB_IN_BYTES × epochsPerMonth)
	// Use ceiling division to ensure small datasets get at least 1 base unit per epoch

	numerator := new(big.Int).Mul(sizeInBytes, pricePerTiBPerMonth)
	denominator := new(big.Int).Mul(big.NewInt(TiBInBytes), big.NewInt(int64(epochsPerMonth)))

	ratePerEpoch := new(big.Int)
	remainder := new(big.Int)
	ratePerEpoch.DivMod(numerator, denominator, remainder)

	// Round up if there's a remainder (ceiling division)
	if remainder.Sign() > 0 {
		ratePerEpoch.Add(ratePerEpoch, big.NewInt(1))
	}

	// Calculate lockup period in epochs
	lockupPeriodEpochs := int64(lockupDays) * EpochsPerDay

	// Calculate lockup allowance
	// lockupAllowance = ratePerEpoch × lockupPeriodInEpochs
	lockupAllowance := new(big.Int).Mul(ratePerEpoch, big.NewInt(lockupPeriodEpochs))

	// Calculate max lockup period in epochs
	maxLockupPeriodEpochs := int64(maxLockupPeriodDays) * EpochsPerDay

	return &AllowanceCalculation{
		SizeInBytes:         new(big.Int).Set(sizeInBytes),
		LockupDays:          lockupDays,
		MaxLockupPeriodDays: maxLockupPeriodDays,
		RateAllowance:       ratePerEpoch,
		LockupAllowance:     lockupAllowance,
		MaxLockupPeriod:     big.NewInt(maxLockupPeriodEpochs),
		LockupPeriodEpochs:  lockupPeriodEpochs,
		RatePerEpoch:        new(big.Int).Set(ratePerEpoch),
	}, nil
}
