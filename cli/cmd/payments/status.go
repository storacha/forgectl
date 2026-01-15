package payments

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"github.com/storacha/forgectl/cli/config"
	"github.com/storacha/forgectl/cli/printer"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/services/types"
)

var (
	payer        string
	listLimit    int64
	listOffset   int64
	outputFormat string
	watchMode    bool
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display account balance, operator approval, and active payment rails",
	RunE:  runStatus,
}

func init() {
	statusCmd.Flags().StringVar(&payer, "payer", "", "payer address")
	cobra.CheckErr(statusCmd.MarkFlagRequired("payer"))
	statusCmd.Flags().Int64Var(&listLimit, "limit", 50, "Maximum number of providers to display")
	statusCmd.Flags().Int64Var(&listOffset, "offset", 0, "Starting offset for pagination")
	statusCmd.Flags().StringVar(&outputFormat, "format", "json", "Output format: json or table")
	statusCmd.Flags().BoolVarP(&watchMode, "watch", "w", false, "Auto-refresh every 30 seconds (one Filecoin epoch)")
}

func runStatus(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(payer) {
		return fmt.Errorf("invalid payer address: %s", payer)
	}
	payerAddr := common.HexToAddress(payer)

	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	inspctr, err := inspector.New(inspector.Config{
		ClientEndpoint:            cfg.RPCUrl,
		PaymentsContractAddress:   cfg.PaymentsAddr(),
		ServiceContractAddress:    cfg.ServiceAddr(),
		ProviderRegistryAddress:   cfg.ServiceRegistryAddr(),
		SessionKeyRegistryAddress: cfg.SessionKeyRegistryAddr(),
		TokenAddress:              cfg.TokenAddr(),
		PDPVerifierAddress:        cfg.VerifierAddr(),
	})
	if err != nil {
		return err
	}

	res, err := inspctr.PaymentsStatus(ctx, cfg.TokenAddr(), payerAddr, 0, 100)
	if err != nil {
		return err
	}

	switch outputFormat {
	case "table":
		return runStatusTUI(res, inspctr, cfg.TokenAddr(), payerAddr, watchMode)
	case "json":
		return printer.AsJson(cmd.OutOrStdout(), res)
	default:
		return fmt.Errorf("unknown format: %s (use 'json' or 'table')", outputFormat)
	}
}

// Styles for the TUI
var (
	// Tab styles
	highlightColor   = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	inactiveTabStyle = lipgloss.NewStyle().
		Border(tabBorderWithBottom("┴", "─", "┴"), true).
		BorderForeground(highlightColor).
		Padding(0, 1)
	activeTabStyle = inactiveTabStyle.
		Border(tabBorderWithBottom("┘", " ", "└"), true)
	windowStyle = lipgloss.NewStyle().
		BorderForeground(highlightColor).
		Padding(1, 2).
		Border(lipgloss.NormalBorder()).
		UnsetBorderTop()
	docStyle = lipgloss.NewStyle().Padding(1, 2, 1, 2)

	// Content styles
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Width(16)
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

func tabBorderWithBottom(left, middle, right string) lipgloss.Border {
	border := lipgloss.RoundedBorder()
	border.BottomLeft = left
	border.Bottom = middle
	border.BottomRight = right
	return border
}

// formatTokenCompact formats a token amount in a compact form for tables
// Shows 4 decimal places for readability
func formatTokenCompact(wei *big.Int) string {
	if wei == nil || wei.Sign() == 0 {
		return "0"
	}
	// Convert to float with 18 decimals
	weiF := new(big.Float).SetInt(wei)
	divisor := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	result := new(big.Float).Quo(weiF, divisor)
	f, _ := result.Float64()
	if f >= 1000 {
		return fmt.Sprintf("$%.1f", f)
	} else if f >= 1 {
		return fmt.Sprintf("$%.2f", f)
	}
	return fmt.Sprintf("$%.4f", f)
}

// Refresh interval - one Filecoin epoch (30 seconds)
const refreshInterval = 30 * time.Second

// Message types for async operations
type tickMsg time.Time
type statusRefreshMsg struct {
	status *types.PaymentStatus
	err    error
}

// statusModel is the Bubbletea model for the payment status TUI
type statusModel struct {
	status       *types.PaymentStatus
	tabs         []string      // Tab names: "Overview", payee addresses
	activeTab    int           // Currently active tab
	tables       []table.Model // One table per payee
	payees       []*types.PayeeStatus
	pricingRates *types.PricingRates

	// For auto-refresh
	inspector    *inspector.Service
	tokenAddr    common.Address
	payerAddr    common.Address
	lastRefresh  time.Time
	refreshError error
	watchMode    bool
}

func (m statusModel) Init() tea.Cmd {
	// Only start auto-refresh ticker if watch mode is enabled
	if m.watchMode {
		return tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return nil
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "right", "l", "tab":
			m.activeTab = min(m.activeTab+1, len(m.tabs)-1)
			return m, nil
		case "left", "h", "shift+tab":
			m.activeTab = max(m.activeTab-1, 0)
			return m, nil
		case "r": // Manual refresh
			return m, m.fetchStatus()
		}

	case tickMsg:
		// Auto-refresh on tick (only if watch mode), then schedule next tick
		if m.watchMode {
			return m, tea.Batch(
				m.fetchStatus(),
				tea.Tick(refreshInterval, func(t time.Time) tea.Msg {
					return tickMsg(t)
				}),
			)
		}
		return m, nil

	case statusRefreshMsg:
		if msg.err != nil {
			m.refreshError = msg.err
			return m, nil
		}
		m.refreshError = nil
		m.lastRefresh = time.Now()
		// Update the model with new data
		m.updateFromStatus(msg.status)
		return m, nil
	}

	// Update the table for the current payee tab
	if len(m.tables) > 0 && m.activeTab < len(m.tables) {
		var cmd tea.Cmd
		m.tables[m.activeTab], cmd = m.tables[m.activeTab].Update(msg)
		return m, cmd
	}

	return m, nil
}

// fetchStatus returns a command that fetches fresh status data
func (m statusModel) fetchStatus() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		status, err := m.inspector.PaymentsStatus(ctx, m.tokenAddr, m.payerAddr, 0, 100)
		return statusRefreshMsg{status: status, err: err}
	}
}

// updateFromStatus updates the model with fresh status data
func (m *statusModel) updateFromStatus(status *types.PaymentStatus) {
	// Sort payees alphabetically by address
	sort.Slice(status.Payees, func(i, j int) bool {
		return status.Payees[i].Address.Hex() < status.Payees[j].Address.Hex()
	})

	m.status = status
	m.payees = status.Payees
	m.pricingRates = status.PricingRates

	// Rebuild tabs (payees only, Overview is always shown above)
	m.tabs = []string{}
	for _, p := range status.Payees {
		m.tabs = append(m.tabs, printer.FormatAddress(p.Address))
	}

	// Clamp activeTab if payees changed
	if len(m.tabs) > 0 && m.activeTab >= len(m.tabs) {
		m.activeTab = len(m.tabs) - 1
	} else if len(m.tabs) == 0 {
		m.activeTab = 0
	}

	// Rebuild tables
	m.tables = buildPayeeTables(status.Payees)
}

func (m statusModel) View() string {
	doc := strings.Builder{}

	// Always render overview at top
	doc.WriteString(m.renderOverview())
	doc.WriteString("\n")

	// Only render payee tabs if there are payees
	if len(m.tabs) > 0 {
		// Render tabs (payees only)
		var renderedTabs []string
		for i, t := range m.tabs {
			var style lipgloss.Style
			isFirst, isLast, isActive := i == 0, i == len(m.tabs)-1, i == m.activeTab
			if isActive {
				style = activeTabStyle
			} else {
				style = inactiveTabStyle
			}
			border, _, _, _, _ := style.GetBorder()
			if isFirst && isActive {
				border.BottomLeft = "│"
			} else if isFirst && !isActive {
				border.BottomLeft = "├"
			} else if isLast && isActive {
				border.BottomRight = "│"
			} else if isLast && !isActive {
				border.BottomRight = "┤"
			}
			style = style.Border(border)
			renderedTabs = append(renderedTabs, style.Render(t))
		}

		row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
		doc.WriteString(row)
		doc.WriteString("\n")

		// Render payee content (activeTab now directly indexes payees)
		if m.activeTab < len(m.payees) {
			content := m.renderPayeeTab(m.activeTab)
			doc.WriteString(windowStyle.Width(lipgloss.Width(row) - windowStyle.GetHorizontalFrameSize()).Render(content))
			doc.WriteString("\n")
		}
	}
	doc.WriteString("\n")

	// Show refresh status (only in watch mode or after manual refresh)
	if m.watchMode || m.refreshError != nil {
		var refreshStatus string
		if m.refreshError != nil {
			refreshStatus = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(
				fmt.Sprintf("Refresh error: %v", m.refreshError))
		} else if m.watchMode && !m.lastRefresh.IsZero() {
			ago := time.Since(m.lastRefresh).Round(time.Second)
			refreshStatus = helpStyle.Render(fmt.Sprintf("Last refresh: %s ago (auto-refresh every 30s)", ago))
		}
		if refreshStatus != "" {
			doc.WriteString(refreshStatus)
			doc.WriteString("\n")
		}
	}

	doc.WriteString(helpStyle.Render("← → switch tabs | ↑ ↓ scroll table | r refresh | q quit"))

	return docStyle.Render(doc.String())
}

func (m statusModel) renderOverview() string {
	var b strings.Builder

	// Calculate aggregate stats across all payees
	totalClaimable := big.NewInt(0)
	totalUnfunded := big.NewInt(0)
	totalProofFaults := big.NewInt(0)
	totalDataStored := big.NewInt(0)
	totalRails := 0
	totalDataSets := 0
	for _, p := range m.status.Payees {
		totalRails += len(p.Rails)
		if p.TotalClaimable != nil {
			totalClaimable = new(big.Int).Add(totalClaimable, p.TotalClaimable)
		}
		if p.TotalUnfunded != nil {
			totalUnfunded = new(big.Int).Add(totalUnfunded, p.TotalUnfunded)
		}
		if p.TotalProofFaults != nil {
			totalProofFaults = new(big.Int).Add(totalProofFaults, p.TotalProofFaults)
		}
		// Aggregate data stored across all datasets
		for _, ds := range p.DataSets {
			if ds.DataSetInfo != nil && ds.DataSetInfo.SizeInBytes != nil {
				totalDataStored = new(big.Int).Add(totalDataStored, ds.DataSetInfo.SizeInBytes)
				totalDataSets++
			}
		}
	}

	// Calculate funding health
	// Note: lockupLastSettledAt only updates on-chain (deposits, settlements, rail changes),
	// so being "behind" is normal and doesn't mean the payer is underfunded.
	epochsBehind := new(big.Int).Sub(m.status.CurrentEpoch, m.status.Payer.Account.LockupLastSettledAt)
	if epochsBehind.Sign() < 0 {
		epochsBehind = big.NewInt(0)
	}

	// Calculate additional lockup needed to cover pending epochs
	additionalLockupNeeded := new(big.Int).Mul(epochsBehind, m.status.Payer.Account.LockupRate)

	// Payer is only ACTUALLY underfunded if available balance can't cover the pending lockup
	isUnderfunded := epochsBehind.Sign() > 0 && m.status.Payer.AvailableBalance.Cmp(additionalLockupNeeded) < 0

	b.WriteString(titleStyle.Render("PAYMENT STATUS OVERVIEW"))
	b.WriteString("\n\n")

	// Current epoch and token
	b.WriteString(labelStyle.Render("Current Epoch:"))
	b.WriteString(valueStyle.Render(printer.FormatBigInt(m.status.CurrentEpoch)))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Token:"))
	b.WriteString(valueStyle.Render(m.status.TokenAddress.Hex()))
	b.WriteString("\n\n")

	// Payer Account with health status
	b.WriteString(titleStyle.Render("PAYER ACCOUNT"))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Address:"))
	b.WriteString(valueStyle.Render(m.status.Payer.Address.Hex()))
	b.WriteString("\n")

	// Funding status indicator - only show underfunded when payer can't cover pending lockup
	b.WriteString(labelStyle.Render("Status:"))
	if isUnderfunded {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).Render(
			"⚠ UNDERFUNDED - providers cannot claim owed funds"))
	} else {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(
			"✓ Funded"))
	}
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Deposited:"))
	b.WriteString(valueStyle.Render(printer.FormatTokenAmount(m.status.Payer.Account.Funds)))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Locked:"))
	b.WriteString(valueStyle.Render(printer.FormatTokenAmount(m.status.Payer.Account.LockupCurrent)))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Available:"))
	if isUnderfunded {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(
			printer.FormatTokenAmount(m.status.Payer.AvailableBalance)))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(" (insufficient)"))
	} else {
		b.WriteString(valueStyle.Render(printer.FormatTokenAmount(m.status.Payer.AvailableBalance)))
	}
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Lockup Rate:"))
	b.WriteString(valueStyle.Render(printer.FormatTokenAmount(m.status.Payer.Account.LockupRate)))
	b.WriteString(" /epoch")
	b.WriteString("\n\n")

	// Funding gap section - only show when actually underfunded
	if isUnderfunded {
		b.WriteString(titleStyle.Render("FUNDING GAP"))
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Last Settled:"))
		b.WriteString(valueStyle.Render(fmt.Sprintf("epoch %s (~%s ago)",
			printer.FormatBigInt(m.status.Payer.Account.LockupLastSettledAt),
			printer.FormatEpochDuration(epochsBehind))))
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Epochs Behind:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(
			printer.FormatEpochsWithDuration(epochsBehind)))
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Deficit:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(
			fmt.Sprintf("%s tokens needed", printer.FormatTokenAmount(additionalLockupNeeded))))
		b.WriteString("\n\n")
	}

	// Payee Summary - aggregate view
	b.WriteString(titleStyle.Render("PAYEE SUMMARY"))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Payees/Rails:"))
	b.WriteString(valueStyle.Render(fmt.Sprintf("%d payees, %d rails", len(m.status.Payees), totalRails)))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Total Stored:"))
	b.WriteString(valueStyle.Render(fmt.Sprintf("%s (%d datasets)", printer.FormatBytes(totalDataStored), totalDataSets)))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Network Fee:"))
	b.WriteString(valueStyle.Render("0.5%"))
	b.WriteString(" (burned on settlement)")
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Total Claimable:"))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(
		printer.FormatTokenAmount(totalClaimable)))
	b.WriteString("\n")
	if totalProofFaults.Sign() > 0 {
		b.WriteString(labelStyle.Render("Total Forfeited:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(
			printer.FormatTokenAmount(totalProofFaults)))
		b.WriteString(" (lost to missed proofs)")
		b.WriteString("\n")
	}
	// Only show unfunded if payer is actually underfunded
	if isUnderfunded && totalUnfunded.Sign() > 0 {
		b.WriteString(labelStyle.Render("Total Unfunded:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(
			printer.FormatTokenAmount(totalUnfunded)))
		b.WriteString(" (awaiting payer deposit)")
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Operator Approval
	b.WriteString(titleStyle.Render("OPERATOR APPROVAL"))
	b.WriteString("\n")
	if m.status.Payer.OperatorApproval.IsApproved {
		b.WriteString(labelStyle.Render("Status:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render("✓ Approved"))
	} else {
		b.WriteString(labelStyle.Render("Status:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✗ Not Approved"))
	}
	b.WriteString("\n")

	// Show usage with percentages
	rateUsage := m.status.Payer.OperatorApproval.RateUsage
	rateAllowance := m.status.Payer.OperatorApproval.RateAllowance
	lockupUsage := m.status.Payer.OperatorApproval.LockupUsage
	lockupAllowance := m.status.Payer.OperatorApproval.LockupAllowance

	b.WriteString(labelStyle.Render("Rate Usage:"))
	b.WriteString(valueStyle.Render(fmt.Sprintf("%s / %s",
		printer.FormatTokenAmount(rateUsage),
		printer.FormatTokenAmount(rateAllowance))))
	if rateAllowance.Sign() > 0 {
		pct := new(big.Float).Quo(new(big.Float).SetInt(rateUsage), new(big.Float).SetInt(rateAllowance))
		pctVal, _ := pct.Float64()
		b.WriteString(fmt.Sprintf(" (%.1f%%)", pctVal*100))
	}
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Lockup Usage:"))
	b.WriteString(valueStyle.Render(fmt.Sprintf("%s / %s",
		printer.FormatTokenAmount(lockupUsage),
		printer.FormatTokenAmount(lockupAllowance))))
	if lockupAllowance.Sign() > 0 {
		pct := new(big.Float).Quo(new(big.Float).SetInt(lockupUsage), new(big.Float).SetInt(lockupAllowance))
		pctVal, _ := pct.Float64()
		b.WriteString(fmt.Sprintf(" (%.1f%%)", pctVal*100))
	}

	return b.String()
}

// isPayerUnderfunded checks if the payer has insufficient funds to cover pending lockup
func (m statusModel) isPayerUnderfunded() bool {
	epochsBehind := new(big.Int).Sub(m.status.CurrentEpoch, m.status.Payer.Account.LockupLastSettledAt)
	if epochsBehind.Sign() <= 0 {
		return false
	}
	additionalLockupNeeded := new(big.Int).Mul(epochsBehind, m.status.Payer.Account.LockupRate)
	return m.status.Payer.AvailableBalance.Cmp(additionalLockupNeeded) < 0
}

func (m statusModel) renderPayeeTab(idx int) string {
	if idx >= len(m.payees) {
		return "No payee data"
	}

	payee := m.payees[idx]
	var b strings.Builder

	totalClaimable := payee.TotalClaimable
	if totalClaimable == nil {
		totalClaimable = big.NewInt(0)
	}
	totalUnfunded := payee.TotalUnfunded
	if totalUnfunded == nil {
		totalUnfunded = big.NewInt(0)
	}
	totalProofFaults := payee.TotalProofFaults
	if totalProofFaults == nil {
		totalProofFaults = big.NewInt(0)
	}

	// Payee header
	b.WriteString(titleStyle.Render("PAYEE"))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Address:"))
	b.WriteString(valueStyle.Render(payee.Address.Hex()))
	b.WriteString("\n\n")

	// Earnings summary - focus on what actually matters
	b.WriteString(titleStyle.Render("EARNINGS SUMMARY"))
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Balance:"))
	b.WriteString(valueStyle.Render(printer.FormatTokenAmount(payee.Account.Funds)))
	b.WriteString(" (can withdraw now)")
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Claimable:"))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(
		printer.FormatTokenAmount(totalClaimable)))
	b.WriteString(" (proven & funded, can settle)")
	b.WriteString("\n")

	// Calculate network fee and net claimable
	totalNetworkFee := big.NewInt(0)
	totalNetClaimable := big.NewInt(0)
	if totalClaimable.Sign() > 0 {
		totalNetworkFee = new(big.Int).Add(totalClaimable, big.NewInt(199))
		totalNetworkFee = new(big.Int).Div(totalNetworkFee, big.NewInt(200))
		totalNetClaimable = new(big.Int).Sub(totalClaimable, totalNetworkFee)
	}

	b.WriteString(labelStyle.Render("Network Fee:"))
	b.WriteString(valueStyle.Render(printer.FormatTokenAmount(totalNetworkFee)))
	b.WriteString(" (0.5%)")
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Net Claimable:"))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render(
		printer.FormatTokenAmount(totalNetClaimable)))
	b.WriteString(" (after fees)")
	b.WriteString("\n")

	// Show forfeited amount prominently if they missed proofs
	if totalProofFaults.Sign() > 0 {
		b.WriteString(labelStyle.Render("Forfeited:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(
			printer.FormatTokenAmount(totalProofFaults)))
		b.WriteString(" (lost to missed proofs)")
		b.WriteString("\n")
	}

	// Only show unfunded if payer is actually underfunded
	if m.isPayerUnderfunded() && totalUnfunded.Sign() > 0 {
		b.WriteString(labelStyle.Render("Unfunded:"))
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(
			printer.FormatTokenAmount(totalUnfunded)))
		b.WriteString(" (awaiting payer settlement)")
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Pricing reference
	if m.pricingRates != nil {
		b.WriteString(titleStyle.Render("CURRENT PRICING"))
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Storage Rate:"))
		b.WriteString(valueStyle.Render(fmt.Sprintf("%s /TiB/month",
			printer.FormatTokenAmount(m.pricingRates.StoragePrice))))
		b.WriteString("\n")
		b.WriteString(labelStyle.Render("Minimum Rate:"))
		b.WriteString(valueStyle.Render(printer.FormatTokenAmount(m.pricingRates.MinimumRate)))
		b.WriteString(" /epoch")
		b.WriteString("\n\n")
	}

	// Rails table
	b.WriteString(titleStyle.Render("RAILS"))
	b.WriteString("\n")

	if idx < len(m.tables) {
		b.WriteString(m.tables[idx].View())
	} else {
		b.WriteString("No rails")
	}

	return b.String()
}

func runStatusTUI(status *types.PaymentStatus, inspctr *inspector.Service, tokenAddr, payerAddr common.Address, watch bool) error {
	// Sort payees alphabetically by address
	sort.Slice(status.Payees, func(i, j int) bool {
		return status.Payees[i].Address.Hex() < status.Payees[j].Address.Hex()
	})

	// Build tabs: payee addresses only (Overview is always shown above tabs)
	tabs := []string{}
	for _, p := range status.Payees {
		tabs = append(tabs, printer.FormatAddress(p.Address))
	}

	m := statusModel{
		status:       status,
		tabs:         tabs,
		activeTab:    0,
		tables:       buildPayeeTables(status.Payees),
		payees:       status.Payees,
		pricingRates: status.PricingRates,
		inspector:    inspctr,
		tokenAddr:    tokenAddr,
		payerAddr:    payerAddr,
		lastRefresh:  time.Now(),
		watchMode:    watch,
	}

	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

// buildPayeeTables creates table models for each payee's rails
func buildPayeeTables(payees []*types.PayeeStatus) []table.Model {
	var tables []table.Model
	for _, payee := range payees {
		// Build dataset size lookup map
		dataSetSizes := make(map[string]*big.Int)
		for _, ds := range payee.DataSets {
			if ds.DataSetInfo != nil && ds.DataSetInfo.DataSetId != nil {
				dataSetSizes[ds.DataSetInfo.DataSetId.String()] = ds.DataSetInfo.SizeInBytes
			}
		}

		columns := []table.Column{
			{Title: "Rail", Width: 6},
			{Title: "DS", Width: 5},
			{Title: "Type", Width: 5},
			{Title: "Size", Width: 9},
			{Title: "Claimable", Width: 12},
			{Title: "Fee", Width: 10},
			{Title: "Net", Width: 12},
			{Title: "Forfeited", Width: 12},
			{Title: "Proofs", Width: 6},
		}

		var rows []table.Row
		for _, rail := range payee.Rails {
			// Format proof success rate - prefer lifetime rate for stability
			proofStr := "N/A"
			if rail.HasValidator {
				if rail.LifetimeTotalEpochs != nil && rail.LifetimeTotalEpochs.Sign() > 0 {
					// Use lifetime rate (more stable, not affected by settlement timing)
					proofStr = fmt.Sprintf("%.0f%%", rail.LifetimeProofRate*100)
				} else {
					// Fallback to current window rate
					proofStr = fmt.Sprintf("%.0f%%", rail.ProofSuccessRate*100)
				}
			}

			// Claimable = actual settleable (funded + proven)
			claimableAmount := rail.ActualSettleable
			if claimableAmount == nil {
				claimableAmount = rail.SettleableAmount
			}
			if claimableAmount == nil {
				claimableAmount = big.NewInt(0)
			}

			// Forfeited = theoretical (max if 100% proofs) - actual (what they can claim)
			// This shows how much they lost to missed proofs
			theoreticalAmount := rail.SettleableAmount
			if theoreticalAmount == nil {
				theoreticalAmount = big.NewInt(0)
			}
			forfeitedAmount := new(big.Int).Sub(theoreticalAmount, claimableAmount)
			if forfeitedAmount.Sign() < 0 {
				forfeitedAmount = big.NewInt(0)
			}

			// Calculate network fee (0.5% with ceiling, matching contract)
			// fee = (amount * 1 + 199) / 200
			networkFee := big.NewInt(0)
			netClaimable := big.NewInt(0)
			if claimableAmount.Sign() > 0 {
				networkFee = new(big.Int).Add(claimableAmount, big.NewInt(199))
				networkFee = new(big.Int).Div(networkFee, big.NewInt(200))
				netClaimable = new(big.Int).Sub(claimableAmount, networkFee)
			}

			// Format dataset ID and size
			dsStr := "-"
			sizeStr := "-"
			if rail.DataSetId != nil && rail.DataSetId.Sign() > 0 {
				dsStr = printer.FormatBigInt(rail.DataSetId)
				if size, ok := dataSetSizes[rail.DataSetId.String()]; ok && size != nil {
					sizeStr = printer.FormatBytes(size)
				}
			}

			rows = append(rows, table.Row{
				printer.FormatBigInt(rail.RailId),
				dsStr,
				printer.FormatRailType(rail.RailType),
				sizeStr,
				formatTokenCompact(claimableAmount),
				formatTokenCompact(networkFee),
				formatTokenCompact(netClaimable),
				formatTokenCompact(forfeitedAmount),
				proofStr,
			})
		}

		t := table.New(
			table.WithColumns(columns),
			table.WithRows(rows),
			table.WithFocused(true),
			table.WithHeight(min(len(rows)+1, 10)),
		)

		s := table.DefaultStyles()
		s.Header = s.Header.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			BorderBottom(true).
			Bold(false)
		s.Selected = s.Selected.
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Bold(false)
		t.SetStyles(s)

		tables = append(tables, t)
	}
	return tables
}
