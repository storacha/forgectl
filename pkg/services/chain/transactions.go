package chain

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Transactor struct {
	tx *bind.TransactOpts
}

type TransactorConfig struct {
	KeystorePath     string
	KeystorePassword string
}

// LoadPrivateKeyFromKeystore loads a private key from an encrypted keystore file
func loadPrivateKeyFromKeystore(keystorePath, password string) (*ecdsa.PrivateKey, error) {
	keystoreFile, err := os.Open(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file: %w", err)
	}
	defer keystoreFile.Close()

	return loadPrivateKetFromReader(keystoreFile, password)
}

func loadPrivateKetFromReader(reader io.Reader, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file: %w", err)
	}

	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, fmt.Errorf("decrypting keystore: %w", err)
	}

	return key.PrivateKey, nil

}

func NewTransactor(chainID *big.Int, cfg TransactorConfig) (*Transactor, error) {
	pk, err := loadPrivateKeyFromKeystore(cfg.KeystorePath, cfg.KeystorePassword)
	if err != nil {
		return nil, err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(pk, chainID)
	if err != nil {
		return nil, fmt.Errorf("creating transactor: %w", err)
	}
	return &Transactor{tx: auth}, nil
}

func (t *Transactor) Auth(ctx context.Context) *bind.TransactOpts {
	t.tx.Context = ctx
	return t.tx
}

// WaitForTransaction waits for a transaction to be mined and returns the receipt
// Uses exponential backoff with a timeout of 5 Filecoin epochs (150 seconds)
func WaitForTransaction(ctx context.Context, client *ethclient.Client, tx *types.Transaction) (*types.Receipt, error) {
	txHash := tx.Hash()

	const (
		filecoinEpochDuration = 30 * time.Second
		maxEpochs             = 5
		maxElapsedTime        = filecoinEpochDuration * maxEpochs // 150 seconds
	)

	// Configure exponential backoff
	// Start with 5 seconds, max 30 seconds (one epoch), with 2x multiplier
	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = 5 * time.Second
	exponentialBackoff.MaxInterval = filecoinEpochDuration

	operation := func() (*types.Receipt, error) {
		receipt, err := client.TransactionReceipt(ctx, txHash)
		if err != nil {
			// Transaction not yet mined, retry
			return nil, err
		}

		if receipt.Status != types.ReceiptStatusSuccessful {
			// Transaction failed, don't retry
			return nil, backoff.Permanent(fmt.Errorf("transaction failed with status %d", receipt.Status))
		}

		// Success
		return receipt, nil
	}

	// Use backoff.Retry with context and options
	receipt, err := backoff.Retry(
		ctx,
		operation,
		backoff.WithBackOff(exponentialBackoff),
		backoff.WithMaxElapsedTime(maxElapsedTime),
		backoff.WithNotify(func(err error, duration time.Duration) {
			fmt.Printf("Transaction not yet confirmed, retrying in %v...\n", duration)
		}),
	)

	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}
