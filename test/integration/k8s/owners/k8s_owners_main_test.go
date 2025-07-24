// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration_k8s

// package owners tests the selection and detection of pod ownership metadata, others than deployment:
// StatefulSet and DaemonSet
package owners

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/obi/test/integration/components/docker"
	"go.opentelemetry.io/obi/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/test/integration/k8s/common"
	"go.opentelemetry.io/obi/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/test/tools"
)

const (
	testTimeout = 3 * time.Minute

	jaegerQueryURL = "http://localhost:36686/api/traces"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
		docker.ImageBuild{Tag: "quay.io/prometheus/prometheus:v2.55.1"},
		docker.ImageBuild{Tag: "otel/opentelemetry-collector-contrib:0.103.0"},
		docker.ImageBuild{Tag: "jaegertracing/all-in-one:1.57"},
		docker.ImageBuild{Tag: "grpcpinger:dev", Dockerfile: k8s.DockerfilePinger},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-owners",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.LocalImage("grpcpinger:dev"),
		kube.LocalImage("quay.io/prometheus/prometheus:v2.55.1"),
		kube.LocalImage("otel/opentelemetry-collector-contrib:0.103.0"),
		kube.LocalImage("jaegertracing/all-in-one:1.57"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-statefulset.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-daemonset.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-job.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-cronjob.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-daemonset.yml"),
	)

	cluster.Run(m)
}
