package chain

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Transactor struct {
	tx *bind.TransactOpts
}

type TransactorConfig struct {
	// either Key or KeystorePath + KeystorePassword must be set
	Key              string
	KeystorePath     string
	KeystorePassword string
}

// loadSigningKeyFromString loads a signing key from a string
// The byte slice can contain either hex-encoded or raw bytes
func loadSigningKeyFromString(data string) (*ecdsa.PrivateKey, error) {
	// Trim whitespace
	keyData := strings.TrimSpace(data)

	// Try hex decoding first
	keyData = strings.TrimPrefix(keyData, "0x")

	keyBytes, err := hex.DecodeString(keyData)
	if err != nil {
		// If hex decoding fails, try using the raw bytes
		keyBytes = []byte(data)
	}

	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key: %w", err)
	}

	return key, nil
}

// loadPrivateKeyFromKeystore loads a private key from an encrypted keystore file
func loadPrivateKeyFromKeystore(keystorePath, password string) (*ecdsa.PrivateKey, error) {
	keystoreFile, err := os.Open(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file: %w", err)
	}
	defer keystoreFile.Close()

	return loadPrivateKeyFromReader(keystoreFile, password)
}

func loadPrivateKeyFromReader(reader io.Reader, password string) (*ecdsa.PrivateKey, error) {
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
	if cfg.Key != "" && cfg.KeystorePath != "" {
		return nil, fmt.Errorf("only one of key or keystore can be provided")
	}

	var pk *ecdsa.PrivateKey
	var err error
	switch {
	case cfg.Key != "":
		pk, err = loadSigningKeyFromString(cfg.Key)
		if err != nil {
			return nil, err
		}
	case cfg.KeystorePath != "":
		pk, err = loadPrivateKeyFromKeystore(cfg.KeystorePath, cfg.KeystorePassword)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("no key or keystore were provided")
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
