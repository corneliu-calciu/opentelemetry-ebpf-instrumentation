// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

func TestTCPLargeBuffers(t *testing.T) {
	pctx := NewEBPFParseContext(nil)
	verifyLargeBuffer := func(traceID [16]uint8, spanID [8]uint8, direction uint8, expectedBuf string) {
		buf, ok := extractTCPLargeBuffer(pctx, traceID, spanID, direction)
		require.True(t, ok, "Expected to find large buffer")
		require.Equal(t, expectedBuf, unix.ByteSliceToString(buf), "Buffer content mismatch")
	}

	firstEvent := TCPLargeBufferHeader{
		Type:      12,
		Direction: 1,
		Len:       10,
	}
	firstEvent.Tp.TraceId = [16]uint8{'1'}
	firstEvent.Tp.SpanId = [8]uint8{'2'}
	firstBuf := "obi rocks!"

	span, drop, err := appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	require.True(t, drop)
	require.Equal(t, request.Span{}, span)

	// Verify normal write
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf)

	secondBuf := "obi rocks twice!"
	firstEvent.Len = uint32(len(secondBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, secondBuf))
	require.NoError(t, err)
	// Verify buffer overwrite
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, secondBuf)

	// Verify second read error
	_, ok := extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction)
	require.False(t, ok, "Expected to not find large buffer after first read")

	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	// Verify no buffer read happens for different traceID/direction
	_, ok = extractTCPLargeBuffer(pctx, [16]uint8{99}, firstEvent.Tp.SpanId, firstEvent.Direction)
	require.False(t, ok, "Expected to not find large buffer for this traceID")
	_, ok = extractTCPLargeBuffer(pctx, firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, 3)
	require.False(t, ok, "Expected to not find large buffer for this direction")
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf)

	// Test append to existing buffer
	firstEvent.Len = 10
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)

	appendEvent := TCPLargeBufferHeader{
		Type:      firstEvent.Type,
		Direction: firstEvent.Direction,
		Len:       6,
		Action:    1, // LargeBufActionAppend
	}
	appendEvent.Tp.TraceId = firstEvent.Tp.TraceId
	appendEvent.Tp.SpanId = firstEvent.Tp.SpanId
	appendBuf := "append"

	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, appendBuf))
	require.NoError(t, err)
	// The buffer should now be firstBuf + appendBuf
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf+appendBuf)

	// Test append to non-existing buffer (should just add a new one)
	newTraceID := [16]uint8{'3'}
	newSpanID := [8]uint8{'4'}
	appendEvent.Tp.TraceId = newTraceID
	appendEvent.Tp.SpanId = newSpanID
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, appendBuf))
	require.NoError(t, err)
	verifyLargeBuffer(newTraceID, newSpanID, firstEvent.Direction, appendBuf)

	// Test multiple appends
	appendEvent.Tp.TraceId = firstEvent.Tp.TraceId
	appendEvent.Tp.SpanId = firstEvent.Tp.SpanId
	// Re-init buffer
	firstEvent.Len = uint32(len(firstBuf))
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, firstEvent, firstBuf))
	require.NoError(t, err)
	// Append twice
	appendEvent.Len = 3
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, "foo"))
	require.NoError(t, err)
	_, _, err = appendTCPLargeBuffer(pctx, toRingbufRecord(t, appendEvent, "bar"))
	require.NoError(t, err)
	verifyLargeBuffer(firstEvent.Tp.TraceId, firstEvent.Tp.SpanId, firstEvent.Direction, firstBuf+"foobar")
}

func toRingbufRecord(t *testing.T, event TCPLargeBufferHeader, buf string) *ringbuf.Record {
	var fixedPart bytes.Buffer
	if err := binary.Write(&fixedPart, binary.LittleEndian, event); err != nil {
		t.Fatalf("failed to write ringbuf record fixed part: %v", err)
	}

	if len(buf) < int(unsafe.Sizeof(TCPLargeBufferHeader{})) {
		buf += strings.Repeat("\x00", int(unsafe.Sizeof(TCPLargeBufferHeader{}))-len(buf))
	}

	fixedPart.Write([]byte(buf))
	return &ringbuf.Record{
		RawSample: fixedPart.Bytes(),
	}
}
