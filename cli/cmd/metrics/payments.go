package metrics

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/telemetry"
	"github.com/storacha/forgectl/pkg/telemetry/metrics"
)

const (
	// FilecoinEpochDuration is approximately 30 seconds per epoch on Filecoin
	FilecoinEpochDuration = 30 * time.Second
)

var (
	paymentsPayerFlag    string
	paymentsOtlpEndpoint string
	paymentsOtlpInsecure bool
)

var paymentsCmd = &cobra.Command{
	Use:   "payments",
	Short: "Export payment channel metrics via OTLP",
	Long: `Export payment channel metrics via OTLP to a collector.

Metrics exported (values in USDFC token units):
  - forgectl_payer_funds: Total deposited funds
  - forgectl_payer_lockup_current: Current lockup amount
  - forgectl_payer_runway_seconds: Estimated runway until funds depleted (in seconds)

This command collects metrics once and exits, making it suitable for cron jobs.`,
	RunE: runPaymentsMetrics,
}

func init() {
	paymentsCmd.Flags().StringVar(&paymentsPayerFlag, "payer", "", "Payer address to monitor (required)")
	cobra.CheckErr(paymentsCmd.MarkFlagRequired("payer"))

	paymentsCmd.Flags().StringVar(&paymentsOtlpEndpoint, "otlp-endpoint", "", "OTLP HTTP endpoint (required, e.g., localhost:4318)")
	cobra.CheckErr(paymentsCmd.MarkFlagRequired("otlp-endpoint"))

	paymentsCmd.Flags().BoolVar(&paymentsOtlpInsecure, "otlp-insecure", false, "Use insecure connection for OTLP")
}

type paymentMetrics struct {
	funds         *telemetry.Float64Gauge
	lockupCurrent *telemetry.Float64Gauge
	runway        *telemetry.Float64Gauge
}

func runPaymentsMetrics(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(paymentsPayerFlag) {
		return fmt.Errorf("invalid payer address: %s", paymentsPayerFlag)
	}
	payerAddr := common.HexToAddress(paymentsPayerFlag)

	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	cfg, err := config.LoadReadOnly()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize telemetry with a short publish interval for one-shot collection
	tel, err := telemetry.New(
		ctx,
		"production",
		"forgectl",
		"0.0.1",
		payerAddr.Hex(),
		metrics.Config{
			Collectors: []metrics.CollectorConfig{
				{
					Endpoint:        paymentsOtlpEndpoint,
					Insecure:        paymentsOtlpInsecure,
					PublishInterval: 5 * time.Second,
				},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to initialize telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := tel.Shutdown(shutdownCtx); err != nil {
			log.Errorw("failed to shutdown telemetry", "error", err)
		}
	}()

	// Create metrics
	meter := tel.Metrics.Meter("forgectl")
	pm, err := newPaymentMetrics(meter)
	if err != nil {
		return fmt.Errorf("failed to create metrics: %w", err)
	}

	// Initialize inspector
	inspctr, err := inspector.New(inspector.Config{
		ClientEndpoint:            cfg.RPCUrl,
		PaymentsContractAddress:   cfg.PaymentsAddr(),
		ServiceContractAddress:    cfg.ServiceAddr(),
		ProviderRegistryAddress:   cfg.ServiceRegistryAddr(),
		SessionKeyRegistryAddress: cfg.SessionKeyRegistryAddr(),
		TokenAddress:              cfg.TokenAddr(),
		PDPVerifierAddress:        cfg.VerifierAddr(),
	})
	if err != nil {
		return fmt.Errorf("failed to create inspector: %w", err)
	}

	tokenAddr := cfg.TokenAddr()
	attrs := []attribute.KeyValue{
		attribute.String("payer", payerAddr.Hex()),
	}

	log.Infow("collecting payment metrics",
		"payer", payerAddr.Hex(),
		"endpoint", paymentsOtlpEndpoint,
	)

	// Collect and record metrics
	if err := collectPaymentMetrics(ctx, inspctr, pm, tokenAddr, payerAddr, attrs); err != nil {
		return fmt.Errorf("failed to collect payment metrics: %w", err)
	}

	log.Info("payment metrics collected successfully")
	return nil
}

func newPaymentMetrics(meter metric.Meter) (*paymentMetrics, error) {
	funds, err := telemetry.NewFloat64Gauge(meter, "forgectl_payer_funds", "Total deposited funds in USDFC", "usdfc")
	if err != nil {
		return nil, err
	}

	lockupCurrent, err := telemetry.NewFloat64Gauge(meter, "forgectl_payer_lockup_current", "Current lockup amount in USDFC", "usdfc")
	if err != nil {
		return nil, err
	}

	runway, err := telemetry.NewFloat64Gauge(meter, "forgectl_payer_runway_seconds", "Estimated runway until funds depleted", "seconds")
	if err != nil {
		return nil, err
	}

	return &paymentMetrics{
		funds:         funds,
		lockupCurrent: lockupCurrent,
		runway:        runway,
	}, nil
}

func collectPaymentMetrics(
	ctx context.Context,
	inspctr *inspector.Service,
	pm *paymentMetrics,
	tokenAddr, payerAddr common.Address,
	attrs []attribute.KeyValue,
) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status, err := inspctr.PaymentsStatus(fetchCtx, tokenAddr, payerAddr, 0, 100)
	if err != nil {
		return fmt.Errorf("failed to fetch payment status: %w", err)
	}

	// Convert wei to token units and record metrics
	fundsTokens := telemetry.WeiToTokens(status.Payer.Account.Funds)
	lockupTokens := telemetry.WeiToTokens(status.Payer.Account.LockupCurrent)

	pm.funds.Record(ctx, fundsTokens, attrs...)
	pm.lockupCurrent.Record(ctx, lockupTokens, attrs...)

	// Calculate runway
	runwaySeconds := calculateRunwaySeconds(
		status.Payer.Account.Funds,
		status.Payer.Account.LockupCurrent,
		status.Payer.Account.LockupRate,
	)
	pm.runway.Record(ctx, runwaySeconds, attrs...)

	log.Infow("recorded payment metrics",
		"funds_usdfc", fundsTokens,
		"lockup_usdfc", lockupTokens,
		"runway_seconds", runwaySeconds,
	)

	return nil
}

// calculateRunwaySeconds calculates how many seconds until the payer runs out of funds.
// Runway in epochs = Available Balance / Lockup Rate
// Runway in seconds = Runway in epochs * FilecoinEpochDuration
func calculateRunwaySeconds(funds, lockupCurrent, lockupRate *big.Int) float64 {
	if funds == nil || lockupCurrent == nil || lockupRate == nil {
		return 0
	}

	// Available balance = funds - lockupCurrent
	availableBalance := new(big.Int).Sub(funds, lockupCurrent)
	if availableBalance.Sign() <= 0 {
		return 0
	}

	// If lockup rate is zero, runway is effectively infinite
	if lockupRate.Sign() == 0 {
		return 0 // Return 0 to indicate no active lockup rate
	}

	// Runway in epochs = available balance / lockup rate
	runwayEpochs := new(big.Float).Quo(
		new(big.Float).SetInt(availableBalance),
		new(big.Float).SetInt(lockupRate),
	)

	// Convert to seconds
	epochSeconds := float64(FilecoinEpochDuration / time.Second)
	runwayEpochsF, _ := runwayEpochs.Float64()
	runwaySeconds := runwayEpochsF * epochSeconds

	return runwaySeconds
}
