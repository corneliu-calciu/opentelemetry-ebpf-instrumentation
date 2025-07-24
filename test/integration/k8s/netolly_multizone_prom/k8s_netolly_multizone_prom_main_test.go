// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration_k8s

package otel

import (
	"log/slog"
	"os"
	"testing"

	"go.opentelemetry.io/obi/test/integration/components/docker"
	"go.opentelemetry.io/obi/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/test/integration/k8s/common"
	"go.opentelemetry.io/obi/test/integration/k8s/common/testpath"
	otel "go.opentelemetry.io/obi/test/integration/k8s/netolly_multizone"
	"go.opentelemetry.io/obi/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.55.1"},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-multizone-prom",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-zone.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.55.1"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape-multizone.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-multizone-client-server.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-netolly-promexport.yml"),
	)

	cluster.Run(m)
}

func TestMultizoneNetworkFlows_Prom(t *testing.T) {
	cluster.TestEnv().Test(t, otel.FeatureMultizoneNetworkFlows())
}
