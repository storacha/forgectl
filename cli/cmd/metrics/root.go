package metrics

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	logging "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/telemetry"
	"github.com/storacha/forgectl/pkg/telemetry/metrics"
)

var log = logging.Logger("forgectl/metrics")

var (
	payerFlag        string
	otlpEndpoint     string
	otlpInsecure     bool
	intervalDuration time.Duration
)

var Cmd = &cobra.Command{
	Use:   "metrics",
	Short: "Export payment metrics via OTLP",
	Long: `Export payment metrics via OTLP to a collector like Grafana Alloy or OpenTelemetry Collector.

Metrics exported (values in USDFC token units):
  - forgectl_payer_funds: Total deposited funds
  - forgectl_payer_lockup_current: Current lockup amount`,
	RunE: runMetrics,
}

func init() {
	Cmd.Flags().StringVar(&payerFlag, "payer", "", "Payer address to monitor (required)")
	cobra.CheckErr(Cmd.MarkFlagRequired("payer"))

	Cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", "", "OTLP HTTP endpoint (required, e.g., localhost:4318)")
	cobra.CheckErr(Cmd.MarkFlagRequired("otlp-endpoint"))

	Cmd.Flags().BoolVar(&otlpInsecure, "otlp-insecure", false, "Use insecure connection for OTLP")
	Cmd.Flags().DurationVar(&intervalDuration, "interval", 30*time.Second, "Collection interval")
}

type payerMetrics struct {
	funds             *telemetry.Float64Gauge
	lockupCurrent     *telemetry.Float64Gauge
	railMissedPeriods *telemetry.Float64Gauge
}

func runMetrics(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(payerFlag) {
		return fmt.Errorf("invalid payer address: %s", payerFlag)
	}
	payerAddr := common.HexToAddress(payerFlag)

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	cfg, err := config.LoadReadOnly()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize telemetry
	tel, err := telemetry.New(
		ctx,
		"production",
		"forgectl",
		"0.0.1",
		payerAddr.Hex(),
		metrics.Config{
			Collectors: []metrics.CollectorConfig{
				{
					Endpoint:        otlpEndpoint,
					Insecure:        otlpInsecure,
					PublishInterval: intervalDuration,
				},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to initialize telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := tel.Shutdown(shutdownCtx); err != nil {
			log.Errorw("failed to shutdown telemetry", "error", err)
		}
	}()

	// Create metrics
	meter := tel.Metrics.Meter("forgectl")
	pm, err := newPayerMetrics(meter)
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

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	tokenAddr := cfg.TokenAddr()
	attrs := []attribute.KeyValue{
		attribute.String("payer", payerAddr.Hex()),
	}

	log.Infow("starting metrics collection",
		"payer", payerAddr.Hex(),
		"endpoint", otlpEndpoint,
		"interval", intervalDuration,
	)

	// Initial collection
	if err := collectAndRecord(ctx, inspctr, pm, tokenAddr, payerAddr, attrs); err != nil {
		log.Warnw("initial collection failed", "error", err)
	}

	// Collection loop
	ticker := time.NewTicker(intervalDuration)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			log.Info("received shutdown signal")
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := collectAndRecord(ctx, inspctr, pm, tokenAddr, payerAddr, attrs); err != nil {
				log.Warnw("collection failed", "error", err)
			}
		}
	}
}

func newPayerMetrics(meter metric.Meter) (*payerMetrics, error) {
	funds, err := telemetry.NewFloat64Gauge(meter, "forgectl_payer_funds", "Total deposited funds in USDFC", "usdfc")
	if err != nil {
		return nil, err
	}

	lockupCurrent, err := telemetry.NewFloat64Gauge(meter, "forgectl_payer_lockup_current", "Current lockup amount in USDFC", "usdfc")
	if err != nil {
		return nil, err
	}

	railMissedPeriods, err := telemetry.NewFloat64Gauge(meter, "forgectl_rail_missed_periods", "Count of proving periods where proof was missed", "periods")
	if err != nil {
		return nil, err
	}

	return &payerMetrics{
		funds:             funds,
		lockupCurrent:     lockupCurrent,
		railMissedPeriods: railMissedPeriods,
	}, nil
}

func collectAndRecord(
	ctx context.Context,
	inspctr *inspector.Service,
	pm *payerMetrics,
	tokenAddr, payerAddr common.Address,
	attrs []attribute.KeyValue,
) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
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

	// Record per-rail missed proving periods
	maxProvingPeriod := status.MaxProvingPeriod
	for _, payee := range status.Payees {
		for _, rail := range payee.Rails {
			if rail.LifetimeTotalEpochs != nil && rail.LifetimeProvenEpochs != nil && maxProvingPeriod > 0 && rail.DataSetId != nil {
				missedEpochs := new(big.Int).Sub(rail.LifetimeTotalEpochs, rail.LifetimeProvenEpochs)
				// Floor division: definite count of fully missed proving periods
				missedPeriods := missedEpochs.Uint64() / maxProvingPeriod

				railAttrs := []attribute.KeyValue{
					attribute.String("payee", payee.Address.Hex()),
					attribute.String("dataset_id", rail.DataSetId.String()),
				}
				pm.railMissedPeriods.Record(ctx, float64(missedPeriods), railAttrs...)
			}
		}
	}

	log.Debugw("recorded metrics",
		"funds_usdfc", fundsTokens,
		"lockup_usdfc", lockupTokens,
	)

	return nil
}
