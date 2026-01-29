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

var (
	faultsPayerFlag    string
	faultsOtlpEndpoint string
	faultsOtlpInsecure bool
)

var faultsCmd = &cobra.Command{
	Use:   "faults",
	Short: "Export proof fault metrics via OTLP",
	Long: `Export proof fault metrics via OTLP to a collector.

Metrics exported:
  - forgectl_rail_missed_periods: Count of proving periods where proof was missed (per rail/dataset)

This command collects metrics once and exits, making it suitable for cron jobs.`,
	RunE: runFaultsMetrics,
}

func init() {
	faultsCmd.Flags().StringVar(&faultsPayerFlag, "payer", "", "Payer address to monitor (required)")
	cobra.CheckErr(faultsCmd.MarkFlagRequired("payer"))

	faultsCmd.Flags().StringVar(&faultsOtlpEndpoint, "otlp-endpoint", "", "OTLP HTTP endpoint (required, e.g., localhost:4318)")
	cobra.CheckErr(faultsCmd.MarkFlagRequired("otlp-endpoint"))

	faultsCmd.Flags().BoolVar(&faultsOtlpInsecure, "otlp-insecure", false, "Use insecure connection for OTLP")
}

type faultMetrics struct {
	railMissedPeriods *telemetry.Float64Gauge
}

func runFaultsMetrics(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(faultsPayerFlag) {
		return fmt.Errorf("invalid payer address: %s", faultsPayerFlag)
	}
	payerAddr := common.HexToAddress(faultsPayerFlag)

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
					Endpoint:        faultsOtlpEndpoint,
					Insecure:        faultsOtlpInsecure,
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
	fm, err := newFaultMetrics(meter)
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

	log.Infow("collecting fault metrics",
		"payer", payerAddr.Hex(),
		"endpoint", faultsOtlpEndpoint,
	)

	// Collect and record metrics
	if err := collectFaultMetrics(ctx, inspctr, fm, tokenAddr, payerAddr); err != nil {
		return fmt.Errorf("failed to collect fault metrics: %w", err)
	}

	log.Info("fault metrics collected successfully")
	return nil
}

func newFaultMetrics(meter metric.Meter) (*faultMetrics, error) {
	railMissedPeriods, err := telemetry.NewFloat64Gauge(meter, "forgectl_rail_missed_periods", "Count of proving periods where proof was missed", "periods")
	if err != nil {
		return nil, err
	}

	return &faultMetrics{
		railMissedPeriods: railMissedPeriods,
	}, nil
}

func collectFaultMetrics(
	ctx context.Context,
	inspctr *inspector.Service,
	fm *faultMetrics,
	tokenAddr, payerAddr common.Address,
) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	status, err := inspctr.PaymentsStatus(fetchCtx, tokenAddr, payerAddr, 0, 100)
	if err != nil {
		return fmt.Errorf("failed to fetch payment status: %w", err)
	}

	// Record per-rail missed proving periods
	maxProvingPeriod := status.MaxProvingPeriod
	for _, payee := range status.Payees {
		for _, rail := range payee.Rails {
			if rail.LifetimeTotalEpochs != nil && rail.LifetimeProvenEpochs != nil && maxProvingPeriod > 0 && rail.DataSetId != nil {
				missedEpochs := new(big.Int).Sub(rail.LifetimeTotalEpochs, rail.LifetimeProvenEpochs)
				// Floor division: definite count of fully missed proving periods
				missedPeriods := missedEpochs.Uint64() / maxProvingPeriod

				railAttrs := []attribute.KeyValue{
					attribute.String("payer", payerAddr.Hex()),
					attribute.String("payee", payee.Address.Hex()),
					attribute.String("dataset_id", rail.DataSetId.String()),
				}
				fm.railMissedPeriods.Record(ctx, float64(missedPeriods), railAttrs...)

				log.Infow("recorded rail fault metrics",
					"payee", payee.Address.Hex(),
					"dataset_id", rail.DataSetId.String(),
					"missed_periods", missedPeriods,
				)
			}
		}
	}

	return nil
}
