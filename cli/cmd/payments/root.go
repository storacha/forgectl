package payments

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "payments",
	Short: "Manage payments contract interactions",
}

func init() {
	Cmd.AddCommand(statusCmd)
	Cmd.AddCommand(calculateCmd)
	Cmd.AddCommand(authorizeSessionCmd)
	Cmd.AddCommand(approveOperatorCmd)
	Cmd.AddCommand(revokeOperatorCmd)
	Cmd.AddCommand(depositCmd)
	Cmd.AddCommand(settleRailCmd)
}
