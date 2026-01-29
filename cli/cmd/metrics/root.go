package metrics

import (
	logging "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

var log = logging.Logger("forgectl/metrics")

var Cmd = &cobra.Command{
	Use:   "metrics",
	Short: "Export metrics via OTLP",
	Long: `Export metrics via OTLP to a collector like Grafana Alloy or OpenTelemetry Collector.

This command supports subcommands for different metric types:
  - payments: Payment channel metrics (funds, lockup, runway)
  - faults: Proof fault metrics (missed proving periods)

Each subcommand collects metrics once and exits, making them suitable for cron jobs.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logging.SetAllLoggers(logging.LevelInfo)
	},
}

func init() {
	Cmd.AddCommand(paymentsCmd)
	Cmd.AddCommand(faultsCmd)
}
