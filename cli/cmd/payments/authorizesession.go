package payments

import (
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/spf13/cobra"
	"github.com/storacha/filecoin-services/go/eip712"
	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	payerservice "github.com/storacha/forgectl/pkg/services/payer"
)

const (
	DefaultDuration = "24h"
)

var DefaultPermissions = slices.Collect(maps.Keys(eip712.EIP712Types))

var (
	address     string
	duration    string
	permissions []string
)

var authorizeSessionCmd = &cobra.Command{
	Use:   "authorize-session",
	Short: "Authorize a session key address with expiry and permissions",
	RunE:  runAuthorizeSession,
}

func init() {
	authorizeSessionCmd.Flags().StringVar(&address, "address", "", "session key address")
	authorizeSessionCmd.Flags().StringVar(&duration, "duration", "24h", "duration until session key expiry (e.g., 30m, 24h, 7d)")
	authorizeSessionCmd.Flags().StringSliceVar(&permissions, "permissions", DefaultPermissions, "list of permissions for the session key (e.g. CreateDataSet, AddPieces, etc)")
	cobra.CheckErr(authorizeSessionCmd.MarkFlagRequired("address"))
}

func runAuthorizeSession(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if !common.IsHexAddress(address) {
		return fmt.Errorf("invalid session key address: %s", address)
	}
	parsedAddr := common.HexToAddress(address)

	permissionBytes := make([][32]byte, 0, len(permissions))
	for _, perm := range permissions {
		permBytes, ok := permissionMap[perm]
		if !ok {
			return fmt.Errorf("unknown permission: %s", perm)
		}
		permissionBytes = append(permissionBytes, permBytes)
	}

	is, err := inspector.New(inspector.Config{
		ClientEndpoint:            cfg.RPCUrl,
		PaymentsContractAddress:   cfg.PaymentsAddr(),
		ServiceContractAddress:    cfg.ServiceAddr(),
		ProviderRegistryAddress:   cfg.ServiceRegistryAddr(),
		TokenAddress:              cfg.TokenAddr(),
		SessionKeyRegistryAddress: cfg.SessionKeyRegistryAddr(),
	})
	if err != nil {
		return err
	}

	chainID, err := is.ChainID(ctx)
	if err != nil {
		return err
	}

	txtr, err := chain.NewTransactor(chainID, chain.TransactorConfig{
		KeystorePath:     cfg.PayerKeystorePath,
		KeystorePassword: cfg.PayerKeystorePassword,
	})
	if err != nil {
		return err
	}

	payerSvc, err := payerservice.New(is, txtr)
	if err != nil {
		return err
	}

	expiry, err := CalculateExpiry(duration)
	if err != nil {
		return fmt.Errorf("calculating expiry: %w", err)
	}
	res, err := payerSvc.AuthorizeSession(ctx, payerservice.AuthorizeSessionParams{
		Address:     parsedAddr,
		Expiry:      expiry,
		Permissions: permissionBytes,
	})
	if err != nil {
		return fmt.Errorf("authorizing session key: %w", err)
	}
	return printer.AsJson(cmd.OutOrStdout(), res)
}

func CalculateExpiry(durationStr string) (*big.Int, error) {
	dur, err := ParseDuration(durationStr)
	if err != nil {
		return nil, fmt.Errorf("parsing duration: %w", err)
	}
	expiry := big.NewInt(time.Now().Add(dur).Unix())
	return expiry, nil
}

var permissionMap map[string][32]byte

func init() {
	typedData := apitypes.TypedData{
		Types: eip712.EIP712Types,
	}
	permissionMap = make(map[string][32]byte, len(eip712.EIP712Types))
	for primaryType := range eip712.EIP712Types {
		permissionMap[primaryType] = [32]byte(typedData.TypeHash(primaryType))
	}
}

/** FYI: everything below is an annoying copy of time.ParseDuration with added "d" and "w" units
which are not in the standard library version **/

var unitMap = map[string]int64{
	"ns": int64(time.Nanosecond),
	"us": int64(time.Microsecond),
	"µs": int64(time.Microsecond), // U+00B5 = micro symbol
	"μs": int64(time.Microsecond), // U+03BC = Greek letter mu
	"ms": int64(time.Millisecond),
	"s":  int64(time.Second),
	"m":  int64(time.Minute),
	"h":  int64(time.Hour),
	"d":  int64(time.Hour) * 24,
	"w":  int64(time.Hour) * 168,
}

// ParseDuration parses a duration string.
// A duration string is a possibly signed sequence of
// decimal numbers, each with optional fraction and a unit suffix,
// such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h", "d", "w".
func ParseDuration(s string) (time.Duration, error) {
	// [-+]?([0-9]*(\.[0-9]*)?[a-z]+)+
	orig := s
	var d int64
	neg := false

	// Consume [-+]?
	if s != "" {
		c := s[0]
		if c == '-' || c == '+' {
			neg = c == '-'
			s = s[1:]
		}
	}
	// Special case: if all that is left is "0", this is zero.
	if s == "0" {
		return 0, nil
	}
	if s == "" {
		return 0, errors.New("time: invalid duration " + quote(orig))
	}
	for s != "" {
		var (
			v, f  int64       // integers before, after decimal point
			scale float64 = 1 // value = v + f/scale
		)

		var err error

		// The next character must be [0-9.]
		if !(s[0] == '.' || '0' <= s[0] && s[0] <= '9') {
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		// Consume [0-9]*
		pl := len(s)
		v, s, err = leadingInt(s)
		if err != nil {
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		pre := pl != len(s) // whether we consumed anything before a period

		// Consume (\.[0-9]*)?
		post := false
		if s != "" && s[0] == '.' {
			s = s[1:]
			pl := len(s)
			f, scale, s = leadingFraction(s)
			post = pl != len(s)
		}
		if !pre && !post {
			// no digits (e.g. ".s" or "-.s")
			return 0, errors.New("time: invalid duration " + quote(orig))
		}

		// Consume unit.
		i := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c == '.' || '0' <= c && c <= '9' {
				break
			}
		}
		if i == 0 {
			return 0, errors.New("time: missing unit in duration " + quote(orig))
		}
		u := s[:i]
		s = s[i:]
		unit, ok := unitMap[u]
		if !ok {
			return 0, errors.New("time: unknown unit " + quote(u) + " in duration " + quote(orig))
		}
		if v > (1<<63-1)/unit {
			// overflow
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
		v *= unit
		if f > 0 {
			// float64 is needed to be nanosecond accurate for fractions of hours.
			// v >= 0 && (f*unit/scale) <= 3.6e+12 (ns/h, h is the largest unit)
			v += int64(float64(f) * (float64(unit) / scale))
			if v < 0 {
				// overflow
				return 0, errors.New("time: invalid duration " + quote(orig))
			}
		}
		d += v
		if d < 0 {
			// overflow
			return 0, errors.New("time: invalid duration " + quote(orig))
		}
	}

	if neg {
		d = -d
	}
	return time.Duration(d), nil
}

func quote(s string) string {
	return "\"" + s + "\""
}

var errLeadingInt = errors.New("time: bad [0-9]*") // never printed

// leadingInt consumes the leading [0-9]* from s.
func leadingInt(s string) (x int64, rem string, err error) {
	i := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if x > (1<<63-1)/10 {
			// overflow
			return 0, "", errLeadingInt
		}
		x = x*10 + int64(c) - '0'
		if x < 0 {
			// overflow
			return 0, "", errLeadingInt
		}
	}
	return x, s[i:], nil
}

// leadingFraction consumes the leading [0-9]* from s.
// It is used only for fractions, so does not return an error on overflow,
// it just stops accumulating precision.
func leadingFraction(s string) (x int64, scale float64, rem string) {
	i := 0
	scale = 1
	overflow := false
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		if overflow {
			continue
		}
		if x > (1<<63-1)/10 {
			// It's possible for overflow to give a positive number, so take care.
			overflow = true
			continue
		}
		y := x*10 + int64(c) - '0'
		if y < 0 {
			overflow = true
			continue
		}
		x = y
		scale *= 10
	}
	return x, scale, s[i:]
}
