package telemetry

import (
	"context"
	"fmt"
	"math/big"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// weiPerToken is 10^18, the number of wei per token (standard ERC-20 decimals)
var weiPerToken = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

type Float64Gauge struct {
	gauge metric.Float64Gauge
}

func NewFloat64Gauge(meter metric.Meter, name string, description string, unit string) (*Float64Gauge, error) {
	if name == "" {
		return nil, fmt.Errorf("gauge name required")
	}
	if description == "" {
		return nil, fmt.Errorf("gauge description required")
	}

	gauge, err := meter.Float64Gauge(
		name,
		metric.WithDescription(description),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gauge %s: %w", name, err)
	}

	return &Float64Gauge{
		gauge: gauge,
	}, nil
}

func (g *Float64Gauge) Record(ctx context.Context, value float64, attrs ...attribute.KeyValue) {
	g.gauge.Record(ctx, value, metric.WithAttributes(attrs...))
}

// WeiToTokens converts a wei value (*big.Int) to token units (float64).
// For ERC-20 tokens with 18 decimals, this divides by 10^18.
// Example: 191020000000000000000 wei -> 191.02 tokens
func WeiToTokens(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	weiFloat := new(big.Float).SetInt(wei)
	divisor := new(big.Float).SetInt(weiPerToken)
	result := new(big.Float).Quo(weiFloat, divisor)
	f, _ := result.Float64()
	return f
}
