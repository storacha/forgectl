package payer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
)

type Service struct {
	*inspector.Service
	tx *chain.Transactor
}

func New(inspector *inspector.Service, transactor *chain.Transactor) (*Service, error) {
	return &Service{
		Service: inspector,
		tx:      transactor,
	}, nil
}

// AuthorizeSessionParams contains parameters for authorizing a session key
type AuthorizeSessionParams struct {
	Address     common.Address
	Expiry      *big.Int
	Permissions [][32]byte
	Origin      string
}

// AuthorizeSession authorizes a session key address with the given expiry and permissions
// by calling the SessionKeyRegistry contract's Login method
func (s *Service) AuthorizeSession(ctx context.Context, params AuthorizeSessionParams) (*ethtypes.Receipt, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.SessionKeyRegistryContract.Login(
			s.tx.Auth(ctx),
			params.Address,
			params.Expiry,
			params.Permissions,
			params.Origin,
		)
	}, "authorizing session key")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}

// SetOperatorApprovalParams contains parameters for setting operator approval
type SetOperatorApprovalParams struct {
	Approve         bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	MaxLockupPeriod *big.Int
}

// SetOperatorApproval approves the service operator using the Payments contract's
// setOperatorApproval method. Uses the TokenAddr and ServiceAddr from the inspector.
func (s *Service) SetOperatorApproval(ctx context.Context, params SetOperatorApprovalParams) (*ethtypes.Receipt, error) {
	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.PaymentsContract.SetOperatorApproval(
			s.tx.Auth(ctx),
			s.TokenAddr,
			s.ServiceAddr,
			params.Approve,
			params.RateAllowance,
			params.LockupAllowance,
			params.MaxLockupPeriod,
		)
	}, "setting operator approval")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}

// Deposit deposits payment into the Payments contract for the payer's account.
// Uses the TokenAddr from the inspector and the From address from the transactor.
func (s *Service) Deposit(ctx context.Context, amount *big.Int) (*ethtypes.Receipt, error) {
	auth := s.tx.Auth(ctx)
	toAddress := auth.From

	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.PaymentsContract.Deposit(
			auth,
			s.TokenAddr,
			toAddress,
			amount,
		)
	}, "depositing payment")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}

// DepositWithPermit deposits payment using an EIP-2612 permit signature.
// This allows depositing without a separate approval transaction.
// Takes only the amount parameter and generates the permit signature automatically.
func (s *Service) DepositWithPermit(ctx context.Context, amount *big.Int) (*ethtypes.Receipt, error) {
	auth := s.tx.Auth(ctx)
	toAddress := auth.From

	// Generate permit signature
	permitSig, deadline, err := s.getPermitSignature(ctx, amount)
	if err != nil {
		return nil, fmt.Errorf("generating permit signature: %w", err)
	}

	tx, err := chain.ExecuteContractCall(func() (*ethtypes.Transaction, error) {
		return s.PaymentsContract.DepositWithPermit(
			auth,
			s.TokenAddr,
			toAddress,
			amount,
			deadline,
			permitSig.V,
			permitSig.R,
			permitSig.S,
		)
	}, "depositing payment with permit")
	if err != nil {
		return nil, err
	}

	receipt, err := chain.WaitForTransaction(ctx, s.Client(), tx)
	if err != nil {
		return nil, fmt.Errorf("waiting for transaction: %w", err)
	}

	return receipt, nil
}

// PermitSignature contains the v, r, s components of an EIP-712 signature
type PermitSignature struct {
	V uint8
	R [32]byte
	S [32]byte
}

// getPermitSignature generates an EIP-2612 permit signature for depositing tokens.
// Returns the signature components and the deadline timestamp.
func (s *Service) getPermitSignature(ctx context.Context, amount *big.Int) (*PermitSignature, *big.Int, error) {
	auth := s.tx.Auth(ctx)
	owner := auth.From
	spender := s.PaymentContractAddr

	// Get the token name from the contract address
	tokenName, err := s.GetTokenName(ctx, s.TokenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("getting token name: %w", err)
	}

	// Get the current nonce for the permit
	nonce, err := s.getTokenNonce(ctx, owner)
	if err != nil {
		return nil, nil, fmt.Errorf("getting token nonce: %w", err)
	}

	// Set deadline to 1 hour from now
	deadline := big.NewInt(time.Now().Add(1 * time.Hour).Unix())

	// Get token domain info
	chainID, err := s.ChainID(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting chain ID: %w", err)
	}

	// Build the EIP-712 domain
	chainIDHex := (*math.HexOrDecimal256)(chainID)
	domain := apitypes.TypedDataDomain{
		Name:              tokenName,
		Version:           "1",
		ChainId:           chainIDHex,
		VerifyingContract: s.TokenAddr.String(),
	}

	// Build the permit message
	message := map[string]interface{}{
		"owner":    owner.String(),
		"spender":  spender.String(),
		"value":    amount,
		"nonce":    nonce,
		"deadline": deadline,
	}

	// Define the EIP-712 types
	types := apitypes.Types{
		"EIP712Domain": {
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
		"Permit": {
			{Name: "owner", Type: "address"},
			{Name: "spender", Type: "address"},
			{Name: "value", Type: "uint256"},
			{Name: "nonce", Type: "uint256"},
			{Name: "deadline", Type: "uint256"},
		},
	}

	// Build the typed data
	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: "Permit",
		Domain:      domain,
		Message:     message,
	}

	// Hash and sign the typed data
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, nil, fmt.Errorf("hashing domain: %w", err)
	}

	messageHash, err := typedData.HashStruct("Permit", message)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing message: %w", err)
	}

	// Construct the signature hash
	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator[:]...)
	rawData = append(rawData, messageHash[:]...)
	signatureHash := crypto.Keccak256(rawData)

	// Sign the hash using the transactor
	v, r, sigS, err := s.tx.Sign(signatureHash)
	if err != nil {
		return nil, nil, fmt.Errorf("signing permit: %w", err)
	}

	return &PermitSignature{V: v, R: r, S: sigS}, deadline, nil
}

// getTokenNonce retrieves the current nonce for an address on the token contract.
// This implements the ERC-2612 nonces() function.
func (s *Service) getTokenNonce(ctx context.Context, owner common.Address) (*big.Int, error) {
	return s.GetTokenNonce(ctx, owner)
}
