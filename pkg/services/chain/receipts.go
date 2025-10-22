package chain

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// GetProviderApprovedEvent parses the ProviderApproved event from a transaction receipt
func GetProviderApprovedEvent(receipt *types.Receipt) (*big.Int, error) {
	// Event signature: ProviderApproved(uint256 indexed providerId)
	eventSignature := crypto.Keccak256Hash([]byte("ProviderApproved(uint256)"))

	for _, log := range receipt.Logs {
		if len(log.Topics) > 0 && log.Topics[0] == eventSignature {
			if len(log.Topics) >= 2 {
				providerId := new(big.Int).SetBytes(log.Topics[1].Bytes())
				return providerId, nil
			}
		}
	}

	return nil, fmt.Errorf("ProviderApproved event not found in receipt")
}
