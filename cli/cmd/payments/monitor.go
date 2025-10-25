package payments

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	logging "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/pkg/database"
	"github.com/storacha/forgectl/pkg/services/inspector"
)

var (
	monitorPayer    string
	monitorInterval time.Duration
	monitorDBURL    string
)

var log = logging.Logger("payments/monitor")

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor payment account, operator, and rails info, storing snapshots in PostgreSQL",
	Long: `Monitor continuously polls PaymentAccountInfo, PaymentOperatorInfo, and PaymentRails
for a specified payer address and stores diff-based snapshots in a PostgreSQL database.

The database uses triggers to efficiently track changes:
- New rows are inserted only when values change
- Unchanged values update only the checked_at timestamp
- This creates a compact history showing when values changed and when they were verified

The command runs indefinitely until interrupted (Ctrl+C).`,
	RunE: runMonitor,
}

func init() {
	monitorCmd.Flags().StringVar(&monitorPayer, "payer", "", "Payer address to monitor (required)")
	cobra.CheckErr(monitorCmd.MarkFlagRequired("payer"))

	monitorCmd.Flags().DurationVar(&monitorInterval, "interval", 30*time.Second, "Polling interval (e.g., 30s, 1m, 5m)")
	monitorCmd.Flags().StringVar(&monitorDBURL, "db-url", "", "Database connection URL (overrides config file)")
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// Validate payer address
	if !common.IsHexAddress(monitorPayer) {
		return fmt.Errorf("invalid payer address: %s", monitorPayer)
	}
	payerAddr := common.HexToAddress(monitorPayer)

	ctx := cmd.Context()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Determine database URL
	dbURL := monitorDBURL
	if dbURL == "" {
		dbURL = cfg.DatabaseURL
	}
	if dbURL == "" {
		return fmt.Errorf("database URL is required: use --db-url flag or set database_url in config file")
	}

	// Connect to database
	log.Infof("Connecting to database...")
	db, err := database.Connect(dbURL)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer db.Close()

	// Apply triggers (idempotent - safe to run multiple times)
	log.Infof("Applying database triggers...")
	if err := db.ApplyTriggers(); err != nil {
		return fmt.Errorf("failed to apply triggers: %w", err)
	}

	// Create inspector service
	log.Infof("Initializing inspector service...")
	inspctr, err := inspector.New(inspector.Config{
		ClientEndpoint:          cfg.RPCUrl,
		PaymentsContractAddress: cfg.PaymentsAddr(),
		ServiceContractAddress:  cfg.ServiceAddr(),
		ProviderRegistryAddress: cfg.ServiceRegistryAddr(),
	})
	if err != nil {
		return err
	}

	tokenAddr := cfg.TokenAddr()

	// Get or create payer-token pair ID (once at startup)
	log.Infof("Resolving payer-token pair...")
	payerTokenPairID, err := db.GetOrCreatePayerTokenPair(payerAddr.Hex(), tokenAddr.Hex())
	if err != nil {
		return fmt.Errorf("failed to get/create payer-token pair: %w", err)
	}
	log.Infof("Monitoring payer-token pair ID: %d", payerTokenPairID)

	log.Infof("Starting monitor for payer %s with %s interval", payerAddr.Hex(), monitorInterval)
	log.Info("Press Ctrl+C to stop")

	// Create ticker for polling
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	// Perform initial poll immediately
	if err := pollAndStore(ctx, inspctr, db, payerTokenPairID, payerAddr, tokenAddr); err != nil {
		log.Errorf("Initial poll failed: %v", err)
	}

	// Poll loop
	for {
		select {
		case <-ctx.Done():
			log.Info("Monitor stopped by user")
			return nil
		case <-ticker.C:
			if err := pollAndStore(ctx, inspctr, db, payerTokenPairID, payerAddr, tokenAddr); err != nil {
				log.Errorf("Poll failed: %v", err)
				// Continue polling even if one poll fails
			}
		}
	}
}

// pollAndStore fetches payment data and stores it in the database
func pollAndStore(ctx context.Context, inspctr *inspector.Service, db *database.DB, payerTokenPairID uint, payer, token common.Address) error {
	log.Debugf("Polling payment data for payer %s...", payer.Hex())

	// Fetch account info
	accountInfo, err := inspctr.PaymentAccountInfo(ctx, token, payer)
	if err != nil {
		return fmt.Errorf("failed to fetch account info: %w", err)
	}

	// Fetch operator info
	operatorInfo, err := inspctr.PaymentOperatorInfo(ctx, token, payer)
	if err != nil {
		return fmt.Errorf("failed to fetch operator info: %w", err)
	}

	// Fetch rails info
	railsInfo, err := inspctr.PaymentsRailsForPayer(ctx, token, payer, 0, 100)
	if err != nil {
		return fmt.Errorf("failed to fetch rails info: %w", err)
	}

	// Create and save account snapshot (trigger handles deduplication)
	accountSnapshot := database.NewPaymentAccountSnapshot(
		payerTokenPairID,
		accountInfo.Funds,
		accountInfo.LockupCurrent,
		accountInfo.LockupRate,
		accountInfo.LockupLastSettledAt,
	)
	if err := db.SaveAccountSnapshot(accountSnapshot); err != nil {
		return err
	}

	// Create and save operator snapshot (trigger handles deduplication)
	operatorSnapshot := database.NewPaymentOperatorSnapshot(
		payerTokenPairID,
		operatorInfo.IsApproved,
		operatorInfo.RateAllowance,
		operatorInfo.LockupAllowance,
		operatorInfo.RateUsage,
		operatorInfo.LockupUsage,
		operatorInfo.MaxLockupPeriod,
	)
	if err := db.SaveOperatorSnapshot(operatorSnapshot); err != nil {
		return err
	}

	// Create and save rails summary (trigger handles deduplication)
	railsSummary := database.NewPaymentRailsSummary(
		payerTokenPairID,
		railsInfo.Total,
		railsInfo.NextOffset,
	)
	if err := db.SaveRailsSummary(railsSummary); err != nil {
		return err
	}

	// Fetch and save each rail's detailed info
	for _, rail := range railsInfo.Rails {
		railDetail, err := inspctr.PaymentsRailInfo(ctx, rail.RailId)
		if err != nil {
			log.Errorf("Failed to fetch rail %s: %v", rail.RailId.String(), err)
			continue // Don't fail entire poll if one rail fails
		}

		// Resolve all FK IDs for this rail
		providerID, err := db.GetOrCreateProvider(
			railDetail.To.Hex(),
			nil, // provider_id from chain - we don't have it yet
			"",  // name - will be filled when we implement ListProviders tracking
			"",  // description
			"",  // payee
		)
		if err != nil {
			log.Errorf("Failed to resolve provider for rail %s: %v", rail.RailId.String(), err)
			continue
		}

		operatorContractID, err := db.GetOrCreateContract(railDetail.Operator.Hex())
		if err != nil {
			log.Errorf("Failed to resolve operator contract for rail %s: %v", rail.RailId.String(), err)
			continue
		}

		validatorContractID, err := db.GetOrCreateContract(railDetail.Validator.Hex())
		if err != nil {
			log.Errorf("Failed to resolve validator contract for rail %s: %v", rail.RailId.String(), err)
			continue
		}

		serviceFeeRecipientContractID, err := db.GetOrCreateContract(railDetail.ServiceFeeRecipient.Hex())
		if err != nil {
			log.Errorf("Failed to resolve service fee recipient contract for rail %s: %v", rail.RailId.String(), err)
			continue
		}

		// Create rail info with all FK IDs
		railInfo := database.NewPaymentRailInfo(
			rail.RailId,
			payerTokenPairID,
			providerID,
			operatorContractID,
			validatorContractID,
			serviceFeeRecipientContractID,
			railDetail.PaymentRate,
			railDetail.LockupPeriod,
			railDetail.LockupFixed,
			railDetail.SettledUpTo,
			railDetail.EndEpoch,
			railDetail.CommissionRateBps,
			rail.IsTerminated,
		)
		if err := db.SaveRailInfo(railInfo); err != nil {
			return err
		}
	}

	log.Infof("Poll complete at %s - processed account, operator, and %d rails",
		accountSnapshot.CheckedAt.Format(time.RFC3339), len(railsInfo.Rails))

	return nil
}
