package chain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/storacha/filecoin-services/go/evmerrors"
)

// ExecuteContractCall wraps a contract method call and automatically handles EVM error parsing.
// This eliminates the need to write error parsing boilerplate at every contract call site.
//
// Usage:
//
//	tx, err := chain.ExecuteContractCall(func() (*types.Transaction, error) {
//	    return s.ServiceContract.AddApprovedProvider(s.tx.Auth(ctx), big.NewInt(int64(providerID)))
//	}, "adding approved provider")
func ExecuteContractCall(fn func() (*types.Transaction, error), context string) (*types.Transaction, error) {
	tx, err := fn()
	if err != nil {
		vmErr, parseErr := evmerrors.ParseRevertFromError(err.Error())
		if parseErr != nil {
			// Failed to parse as an EVM revert, return original error
			return nil, fmt.Errorf("%s: %w", context, err)
		}
		// Successfully parsed EVM revert message
		return nil, fmt.Errorf("%s: %w", context, vmErr)
	}
	return tx, nil
}