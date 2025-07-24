// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"

	"go.opentelemetry.io/obi/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
