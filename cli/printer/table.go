package printer

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// Token decimals for ERC20 tokens (standard is 18)
	TokenDecimals = 18
)

// FormatAddress truncates an address for display: 0x1234...abcd
func FormatAddress(addr common.Address) string {
	hex := addr.Hex()
	if len(hex) <= 13 {
		return hex
	}
	return hex[:6] + "..." + hex[len(hex)-4:]
}

// FormatBigInt formats a *big.Int with thousand separators
func FormatBigInt(n *big.Int) string {
	if n == nil {
		return "0"
	}
	return addThousandSeparators(n.String())
}

// FormatTokenAmount formats wei to token amount with full precision (18 decimals)
func FormatTokenAmount(wei *big.Int) string {
	if wei == nil {
		return "$0.000000000000000000"
	}

	// Handle zero
	if wei.Sign() == 0 {
		return "$0.000000000000000000"
	}

	// Convert to string
	str := wei.String()
	negative := false
	if str[0] == '-' {
		negative = true
		str = str[1:]
	}

	// Pad with leading zeros if needed
	for len(str) < TokenDecimals+1 {
		str = "0" + str
	}

	// Split into integer and decimal parts
	intPart := str[:len(str)-TokenDecimals]
	decPart := str[len(str)-TokenDecimals:]

	// Add thousand separators to integer part
	intPart = addThousandSeparators(intPart)

	result := intPart + "." + decPart
	if negative {
		result = "-" + result
	}
	return fmt.Sprintf("$%s", result)
}

// addThousandSeparators adds commas as thousand separators
func addThousandSeparators(s string) string {
	if len(s) <= 3 {
		return s
	}

	// Handle negative numbers
	negative := false
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}

	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
		if len(s) > remainder {
			result.WriteString(",")
		}
	}

	for i := remainder; i < len(s); i += 3 {
		result.WriteString(s[i : i+3])
		if i+3 < len(s) {
			result.WriteString(",")
		}
	}

	if negative {
		return "-" + result.String()
	}
	return result.String()
}

// Box drawing characters for Unicode tables
const (
	BoxHorizontal       = "─"
	BoxVertical         = "│"
	BoxTopLeft          = "┌"
	BoxTopRight         = "┐"
	BoxBottomLeft       = "└"
	BoxBottomRight      = "┘"
	BoxVerticalRight    = "├"
	BoxVerticalLeft     = "┤"
	BoxHorizontalDown   = "┬"
	BoxHorizontalUp     = "┴"
	BoxCross            = "┼"
	BoxDoubleHorizontal = "═"
	BoxSingleHorizontal = "─"
)

// RepeatString repeats a string n times
func RepeatString(s string, n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(s, n)
}

// PrintSectionHeader prints a section header with double line
func PrintSectionHeader(title string, width int) string {
	return fmt.Sprintf("%s\n%s", title, RepeatString(BoxDoubleHorizontal, width))
}

// PrintSubsectionHeader prints a subsection header with single line
func PrintSubsectionHeader(title string, width int) string {
	return fmt.Sprintf("%s\n%s", title, RepeatString(BoxSingleHorizontal, width))
}

// FormatBytes formats bytes to human-readable format (e.g., "1.5 TiB", "500 GiB")
func FormatBytes(bytes *big.Int) string {
	if bytes == nil || bytes.Sign() == 0 {
		return "0 B"
	}

	// Use binary units (1024-based)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	divisor := big.NewInt(1024)

	// Work with float for precision
	value := new(big.Float).SetInt(bytes)
	unitIdx := 0

	threshold := new(big.Float).SetInt64(1024)
	for value.Cmp(threshold) >= 0 && unitIdx < len(units)-1 {
		value.Quo(value, new(big.Float).SetInt(divisor))
		unitIdx++
	}

	// Format with appropriate precision
	f, _ := value.Float64()
	if unitIdx == 0 {
		return fmt.Sprintf("%.0f %s", f, units[unitIdx])
	}
	if f >= 100 {
		return fmt.Sprintf("%.1f %s", f, units[unitIdx])
	}
	return fmt.Sprintf("%.2f %s", f, units[unitIdx])
}

// FormatBytesExact formats bytes with human-readable and exact value
func FormatBytesExact(bytes *big.Int) string {
	if bytes == nil || bytes.Sign() == 0 {
		return "0 B"
	}
	human := FormatBytes(bytes)
	// Only show exact bytes if it's more than 1 KiB
	if bytes.Cmp(big.NewInt(1024)) < 0 {
		return human
	}
	return fmt.Sprintf("%s (%s bytes)", human, FormatBigInt(bytes))
}

// FormatRailType returns a compact string for rail type
func FormatRailType(railType string) string {
	switch railType {
	case "PDP":
		return "PDP"
	case "CDN":
		return "CDN"
	case "CacheMiss":
		return "Cache"
	default:
		return "?"
	}
}

// FormatEarningsComparison formats actual vs theoretical earnings
// Returns "actual (of theoretical)" if different, otherwise just "actual"
func FormatEarningsComparison(actual, theoretical *big.Int) string {
	actualStr := FormatTokenAmount(actual)
	if theoretical != nil && actual != nil && theoretical.Cmp(actual) != 0 {
		return fmt.Sprintf("%s (of %s)", actualStr, FormatTokenAmount(theoretical))
	}
	return actualStr
}

// FilecoinEpochDuration is the duration of a single Filecoin epoch (30 seconds)
const FilecoinEpochSeconds = 30

// FormatEpochDuration converts epochs to a human-readable duration string
// Filecoin epochs are 30 seconds each
func FormatEpochDuration(epochs *big.Int) string {
	if epochs == nil || epochs.Sign() <= 0 {
		return "0s"
	}

	totalSeconds := new(big.Int).Mul(epochs, big.NewInt(FilecoinEpochSeconds)).Int64()

	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60

	if days > 0 {
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if hours > 0 {
		if minutes > 0 {
			return fmt.Sprintf("%dh %dm", hours, minutes)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", totalSeconds)
}

// FormatEpochsWithDuration formats epochs with duration in parentheses
// e.g., "15,885 (~5d 12h)"
func FormatEpochsWithDuration(epochs *big.Int) string {
	if epochs == nil || epochs.Sign() <= 0 {
		return "0"
	}
	return fmt.Sprintf("%s (~%s)", FormatBigInt(epochs), FormatEpochDuration(epochs))
}
