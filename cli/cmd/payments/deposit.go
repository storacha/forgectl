package payments

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	payerservice "github.com/storacha/forgectl/pkg/services/payer"
)

var (
	amount string
)

var depositCmd = &cobra.Command{
	Use:   "deposit",
	Short: "Deposit payment into the Payments contract",
	Long: `Deposit payment into the Payments contract for the payer's account.
This calls the Payments contract's deposit method using the token address from the config and the payer's address as the recipient.`,
	RunE: runDeposit,
}

func init() {
	depositCmd.Flags().StringVar(&amount, "amount", "", "amount to deposit (in token base units)")
	cobra.CheckErr(depositCmd.MarkFlagRequired("amount"))
}

func runDeposit(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	is, err := inspector.New(inspector.Config{
		ClientEndpoint:            cfg.RPCUrl,
		PaymentsContractAddress:   cfg.PaymentsAddr(),
		ServiceContractAddress:    cfg.ServiceAddr(),
		ProviderRegistryAddress:   cfg.ServiceRegistryAddr(),
		TokenAddress:              cfg.TokenAddr(),
		SessionKeyRegistryAddress: cfg.SessionKeyRegistryAddr(),
	})
	if err != nil {
		return err
	}
	tokenDecimals, err := is.QueryTokenDecimals(ctx, cfg.TokenAddr())
	if err != nil {
		return err
	}

	// Parse amount to base units
	amountBig, err := parseAmountToBaseUnits(amount, int(tokenDecimals))
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}

	chainID, err := is.ChainID(ctx)
	if err != nil {
		return err
	}

	txtr, err := chain.NewTransactor(chainID, chain.TransactorConfig{
		KeystorePath:     cfg.PayerKeystorePath,
		KeystorePassword: cfg.PayerKeystorePassword,
	})
	if err != nil {
		return err
	}

	payerSvc, err := payerservice.New(is, txtr)
	if err != nil {
		return err
	}

	res, err := payerSvc.DepositWithPermit(ctx, amountBig)
	if err != nil {
		return fmt.Errorf("depositing payment: %w", err)
	}

	return printer.AsJson(cmd.OutOrStdout(), res)
}

// parseAmountToBaseUnits parses a decimal amount string to base units
// For example: "1.5" with decimals=18 -> 1500000000000000000
func parseAmountToBaseUnits(amount string, decimals int) (*big.Int, error) {
	// Split on decimal point
	parts := strings.Split(amount, ".")
	if len(parts) > 2 {
		return nil, fmt.Errorf("invalid number format: multiple decimal points")
	}

	// Get the integer part
	integerPart := parts[0]
	if integerPart == "" {
		integerPart = "0"
	}

	// Get the fractional part
	fractionalPart := ""
	if len(parts) == 2 {
		fractionalPart = parts[1]
	}

	// Check if fractional part has more digits than decimals
	if len(fractionalPart) > decimals {
		return nil, fmt.Errorf("too many decimal places (max %d)", decimals)
	}

	// Pad fractional part with zeros to match decimals
	fractionalPart = fractionalPart + strings.Repeat("0", decimals-len(fractionalPart))

	// Combine integer and fractional parts
	fullNumber := integerPart + fractionalPart

	// Parse as big.Int
	result := new(big.Int)
	result, ok := result.SetString(fullNumber, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse number")
	}

	return result, nil
}
