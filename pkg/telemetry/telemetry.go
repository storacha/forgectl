package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/storacha/forgectl/pkg/telemetry/metrics"
)

type shutdownFn func(context.Context) error

type Telemetry struct {
	Metrics     metric.MeterProvider
	shutdownFns []shutdownFn
}

func New(
	ctx context.Context,
	environment, serviceName, serviceVersion, instanceID string,
	metricCollectors metrics.Config,
	resourceOpts ...resource.Option,
) (*Telemetry, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("telemetry service name required")
	}
	if serviceVersion == "" {
		return nil, fmt.Errorf("telemetry service version required")
	}
	if instanceID == "" {
		return nil, fmt.Errorf("telemetry instance id required")
	}
	if environment == "" {
		return nil, fmt.Errorf("telemetry environment required")
	}

	var rsrcOpts []resource.Option
	rsrcOpts = append(rsrcOpts, resource.WithAttributes(
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(serviceVersion),
		semconv.ServiceInstanceIDKey.String(instanceID),
		semconv.DeploymentEnvironmentKey.String(environment),
	))
	rsrcOpts = append(rsrcOpts, resourceOpts...)

	rsrc, err := resource.New(ctx, rsrcOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	metricsProvider, metricShutdownFn, err := metrics.NewProvider(ctx, rsrc, metricCollectors)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics provider: %w", err)
	}

	otel.SetMeterProvider(metricsProvider)

	return &Telemetry{
		Metrics:     metricsProvider,
		shutdownFns: []shutdownFn{metricShutdownFn},
	}, nil
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	for _, fn := range t.shutdownFns {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}
