// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	prom2 "go.opentelemetry.io/obi/test/integration/components/prom"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx := t.Context()

	promPort, err := test.FreeTCPPort()
	require.NoError(t, err)

	// Flows pipeline that will discard any network flow not matching the "TCP" transport attribute
	flows := Flows{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Path:     "/metrics",
				Port:     promPort,
				Features: []string{otel.FeatureNetwork},
				TTL:      time.Hour,
			},
			Filters: filter.AttributesConfig{
				Network: map[string]filter.MatchDefinition{"transport": {Match: "TCP"}},
			},
			Attributes: obi.Attributes{Select: attributes.Selection{
				attributes.NetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "iface.direction", "dst_port", "iface", "src_port", "transport"},
				},
			}},
		},
		interfaceNamer: func(_ int) string { return "fakeiface" },
	}

	ringBuf := make(chan []*ebpf.Record, 10)
	// override eBPF flow fetchers
	newMapTracer = func(_ *Flows, _ *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
		return func(_ context.Context) {}
	}
	newRingBufTracer = func(_ *Flows, out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
		return func(_ context.Context) {
			for i := range ringBuf {
				out.Send(i)
			}
		}
	}

	runner, err := flows.buildPipeline(ctx)
	require.NoError(t, err)

	go runner.Start(ctx)

	ringBuf <- []*ebpf.Record{
		fakeRecord(transport.UDP, 123, 456),
		fakeRecord(transport.TCP, 789, 1011),
		fakeRecord(transport.UDP, 333, 444),
	}
	ringBuf <- []*ebpf.Record{
		fakeRecord(transport.TCP, 1213, 1415),
		fakeRecord(transport.UDP, 3333, 8080),
	}

	test.Eventually(t, timeout, func(t require.TestingT) {
		metrics, err := prom2.Scrape(fmt.Sprintf("http://localhost:%d/metrics", promPort))
		require.NoError(t, err)

		// assuming metrics returned alphabetically ordered
		assert.Equal(t, []prom2.ScrapedMetric{
			{Name: "obi_network_flow_bytes_total", Labels: map[string]string{
				"obi_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1011", "iface": "fakeiface", "src_port": "789", "transport": "TCP",
			}},
			{Name: "obi_network_flow_bytes_total", Labels: map[string]string{
				"obi_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1415", "iface": "fakeiface", "src_port": "1213", "transport": "TCP",
			}},
			// standard prometheus metrics. Leaving them here to simplify test verification
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "encoding"}},
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "gathering"}},
		}, metrics)
	})
}

func fakeRecord(protocol transport.Protocol, srcPort, dstPort uint16) *ebpf.Record {
	return &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{
			SrcPort: srcPort, DstPort: dstPort, TransportProtocol: uint8(protocol),
		},
	}}
}
