package cmd

import (
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/storacha/forgectl/cli/cmd/metrics"
	"github.com/storacha/forgectl/cli/cmd/payments"
	"github.com/storacha/forgectl/cli/cmd/providers"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "forgctl",
	Short: "A CLI for managing the various Forge contracts",
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./service-operator.yaml)")

	rootCmd.PersistentFlags().String("rpc-url", "", "Ethereum RPC endpoint URL (required)")
	rootCmd.PersistentFlags().String("service-contract-address", "", "FilecoinWarmStorageService contract address (required)")
	rootCmd.PersistentFlags().String("verifier-contract-address", "", "PDPVerifier contract address (required)")
	rootCmd.PersistentFlags().String("service-registry-contract-address", "", "ServiceProviderRegistry contract address (required)")
	rootCmd.PersistentFlags().String("payments-contract-address", "", "Payments contract address (required)")
	rootCmd.PersistentFlags().String("token-contract-address", "", "USDFC token contract address (required)")
	rootCmd.PersistentFlags().String("session-key-registry-contract-address", "", "SessionKeyRegistry contract address (required)")

	rootCmd.PersistentFlags().String("keystore-path", "", "path to keystore")
	rootCmd.PersistentFlags().String("keystore-password", "", "password to decrypt keystore")
	rootCmd.PersistentFlags().String("payer-keystore-path", "", "path to payer keystore")
	rootCmd.PersistentFlags().String("payer-keystore-password", "", "password to decrypt payer keystore")

	cobra.CheckErr(viper.BindPFlag("rpc_url", rootCmd.PersistentFlags().Lookup("rpc-url")))
	cobra.CheckErr(viper.BindPFlag("service_contract_address", rootCmd.PersistentFlags().Lookup("service-contract-address")))
	cobra.CheckErr(viper.BindPFlag("verifier_contract_address", rootCmd.PersistentFlags().Lookup("verifier-contract-address")))
	cobra.CheckErr(viper.BindPFlag("service_registry_contract_address", rootCmd.PersistentFlags().Lookup("service-registry-contract-address")))
	cobra.CheckErr(viper.BindPFlag("payments_contract_address", rootCmd.PersistentFlags().Lookup("payments-contract-address")))
	cobra.CheckErr(viper.BindPFlag("token_contract_address", rootCmd.PersistentFlags().Lookup("token-contract-address")))
	cobra.CheckErr(viper.BindPFlag("session_key_registry_contract_address", rootCmd.PersistentFlags().Lookup("session-key-registry-contract-address")))
	cobra.CheckErr(viper.BindPFlag("keystore_path", rootCmd.PersistentFlags().Lookup("keystore-path")))
	cobra.CheckErr(viper.BindPFlag("keystore_password", rootCmd.PersistentFlags().Lookup("keystore-password")))
	cobra.CheckErr(viper.BindPFlag("payer_keystore_path", rootCmd.PersistentFlags().Lookup("payer-keystore-path")))
	cobra.CheckErr(viper.BindPFlag("payer_keystore_password", rootCmd.PersistentFlags().Lookup("payer-keystore-password")))

	rootCmd.AddCommand(providers.Cmd)
	rootCmd.AddCommand(payments.Cmd)
	rootCmd.AddCommand(metrics.Cmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("FORGECTL")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Don't error if config file is not found
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			cobra.CheckErr(err)
		}
	}
}

func Execute(ctx context.Context) error {
	return rootCmd.ExecuteContext(ctx)
}
