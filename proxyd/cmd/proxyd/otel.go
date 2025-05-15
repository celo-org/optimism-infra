package main

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	// "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Custom sampler: only sample spans if parent has "force_sample=true" attribute
type attrBasedSampler struct{}

func (s *attrBasedSampler) ShouldSample(p trace.SamplingParameters) trace.SamplingResult {
	for _, attr := range p.Attributes {
		if attr.Key == "force_sample" && attr.Value.AsBool() {
			return trace.SamplingResult{Decision: trace.RecordAndSample}
		}
	}
	return trace.SamplingResult{Decision: trace.Drop}
}

func (s *attrBasedSampler) Description() string {
	return "Sample if parent has force_sample=true"
}

// setupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func setupOTelSDK(ctx context.Context, endpoint string, insecure bool, serviceName string) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Set up propagator.
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	// Set up trace provider.
	tracerProvider, err := newTracerProvider(endpoint, insecure, serviceName)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	return
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTracerProvider(endpoint string, insecure bool, serviceName string) (*trace.TracerProvider, error) {
	// traceExporter, err := stdouttrace.New(
	// 	stdouttrace.WithPrettyPrint())
	// if err != nil {
	// 	return nil, err
	// }

	ctx := context.Background()
	// Configure OTLP exporter to Grafana Agent
	var traceExporter *otlptrace.Exporter
	var err error
	if insecure {
		traceExporter, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}
	} else {
		traceExporter, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(endpoint),
		)
		if err != nil {
			return nil, err
		}
	}

	tracerProvider := trace.NewTracerProvider(
		trace.WithSampler(trace.ParentBased(&attrBasedSampler{})),
		trace.WithBatcher(traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			trace.WithBatchTimeout(time.Second)),
		trace.WithResource(resource.NewWithAttributes(
			// Add resource attributes (e.g., service name)
			semconv.SchemaURL,
			attribute.String("service.name", serviceName),
		)),
	)
	return tracerProvider, nil
}
