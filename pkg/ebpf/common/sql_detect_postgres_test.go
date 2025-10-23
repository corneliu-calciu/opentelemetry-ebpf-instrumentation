// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresMessagesIterator(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    []postgresMessage
		wantErr bool
	}{
		{
			name: "single valid message",
			// Message: type 'Q', length 11, data "SELECT\x00"
			buf: append([]byte{'Q', 0, 0, 0, 11}, append([]byte("SELECT"), 0)...),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name: "multiple valid messages",
			buf: func() []byte {
				// First message: type 'Q', length 11, data "SELECT\x00"
				// Second message: type 'Q', length 11, data "COMMIT\x00"
				b := []byte{'Q', 0, 0, 0, 11}
				b = append(b, append([]byte("SELECT"), 0)...)
				b = append(b, 'Q', 0, 0, 0, 11)
				b = append(b, append([]byte("COMMIT"), 0)...)
				return b
			}(),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
				{
					typ:  "QUERY",
					data: append([]byte("COMMIT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name:    "buffer too short for header",
			buf:     []byte{'Q', 0, 0, 0},
			want:    nil,
			wantErr: true,
		},
		{
			name: "buffer too short for message data",
			// Header says length 20, but only 10 bytes in buffer (5 header + 5 data)
			buf:     append([]byte{'Q', 0, 0, 0, 20}, []byte("short")...),
			want:    nil,
			wantErr: true,
		},
		{
			name: "zero length message",
			// Header says length 4 (header only, no data)
			buf: []byte{'Q', 0, 0, 0, 4},
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: []byte{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []postgresMessage
			it := &postgresMessageIterator{buf: tt.buf}
			for {
				msg := it.next()
				if it.isEOF() {
					break
				}
				got = append(got, msg)
			}
			if tt.wantErr {
				assert.Error(t, it.err, "postgresMessageIterator should return an error for test case: %s", tt.name)
				return
			}
			require.NoError(t, it.err, "postgresMessageIterator returned unexpected error for test case: %s", tt.name)
			assert.Len(t, got, len(tt.want), "postgresMessageIterator returned unexpected number of messages for test case: %s", tt.name)
			assert.Equal(t, tt.want, got, "postgresMessageIterator returned unexpected messages for test case: %s", tt.name)
		})
	}
}

func TestPostgresMessagesIteratorNoAllocs(t *testing.T) {
	buf := func() []byte {
		// First message: type 'Q', length 11, data "SELECT\x00"
		// Second message: type 'Q', length 11, data "COMMIT\x00"
		b := []byte{'Q', 0, 0, 0, 11}
		b = append(b, append([]byte("SELECT"), 0)...)
		b = append(b, 'Q', 0, 0, 0, 11)
		b = append(b, append([]byte("COMMIT"), 0)...)
		return b
	}()

	allocs := testing.AllocsPerRun(1000, func() {
		it := &postgresMessageIterator{buf: buf}

		for {
			it.next()
			if it.isEOF() {
				break
			}
		}
	})

	if allocs != 0 {
		t.Errorf("MessageIterator allocated %v allocs per run; want 0", allocs)
	}
}

func TestParsePostgresBindCommand(t *testing.T) {
	tests := []struct {
		name          string
		buf           []byte
		wantStatement string
		wantPortal    string
		wantArgs      []string
		wantErr       string
	}{
		{
			name: "valid bind command with empty statement and portal",
			// 'B' + len(14) + stmt(null) + portal(null) + 1 format code + 0 params
			buf: append([]byte{66, 0, 0, 0, 14, 0, 0, 0, 1, 0, 1, 0, 0},
				make([]byte, 243)...), // Pad to 256
			wantStatement: "",
			wantPortal:    "",
			wantArgs:      []string{},
			wantErr:       "",
		},
		{
			name: "valid bind command with statement and portal",
			// 'B' + len(20) + "s1" + null + "p1" + null + 1 format code + 0 params
			buf: append([]byte{66, 0, 0, 0, 20, 115, 49, 0, 112, 49, 0, 0, 1, 0, 1, 0, 0},
				make([]byte, 239)...), // Pad to 256
			wantStatement: "s1",
			wantPortal:    "p1",
			wantArgs:      []string{},
			wantErr:       "",
		},
		{
			name: "valid bind command with one param",
			// Based on working test format
			buf: append([]byte{66, 0, 0, 0, 22, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 2, 97, 98},
				make([]byte, 237)...), // Pad to 256
			wantStatement: "",
			wantPortal:    "",
			wantArgs:      []string{"ab"},
			wantErr:       "",
		},
		{
			name: "truncated buffer - too short for statement",
			// Create a buffer that's too short during statement parsing
			buf:     []byte{'B', 0, 0, 0, 20, 's', 't', 'm', 't'}, // No null terminator, ends
			wantErr: "too short, while parsing statement",
		},
		{
			name:    "truncated buffer - too short for portal",
			buf:     []byte{'B', 0, 0, 0, 20, 's', 't', 0, 'p', 'o', 'r', 't'}, // No null term
			wantErr: "too short, while parsing portal",
		},
		{
			name: "truncated buffer - too short for format codes count (lines 104-106)",
			// This specifically tests the bounds check at lines 104-106
			// After parsing statement and portal, we need 2 bytes for format codes count
			// buf[0]='B', buf[1:5]=len(9), buf[5]='s', buf[6]=0, buf[7]='p', buf[8]=0
			// ptr would be at 9, need to read buf[9:11], but size=9
			buf:     []byte{66, 0, 0, 0, 9, 115, 0, 112, 0},
			wantErr: "too short, while parsing format codes",
		},
		{
			name:    "truncated buffer - too short inside format codes loop",
			buf:     []byte{66, 0, 0, 0, 20, 0, 0, 0, 2, 0, 0}, // 2 format codes but only 1 present
			wantErr: "too short, while parsing format codes",
		},
		{
			name: "truncated buffer - too short for params count (lines 118-120)",
			// This tests the bounds check at lines 118-120
			// buf[0]='B', buf[1:5]=len(11), buf[5]=0(stmt), buf[6]=0(portal),
			// buf[7:9]=formats(0), buf[9]=partial params count
			buf:     []byte{66, 0, 0, 0, 11, 0, 0, 0, 0, 0}, // Only 1 byte for params count (need 2)
			wantErr: "too short, while parsing params count",
		},
		{
			name:    "truncated buffer - too short for params",
			buf:     []byte{66, 0, 0, 0, 20, 0, 0, 0, 0, 0, 1}, // Says 1 param but no length field
			wantErr: "too short, while parsing params",
		},
		{
			name: "truncated param data",
			// Param claims to be 10 bytes but buffer only has 5
			buf:           []byte{66, 0, 0, 0, 50, 0, 0, 0, 0, 0, 1, 0, 0, 0, 10, 's', 'h', 'o', 'r', 't'},
			wantStatement: "",
			wantPortal:    "",
			wantArgs:      []string{"short"}, // Gracefully handles truncated param
			wantErr:       "",
		},
		{
			name: "reproduces original panic scenario - buffer capacity 128",
			// The original panic: "slice bounds out of range [:129] with capacity 128"
			// Happens when buffer is 128 bytes and code tries to read beyond it
			buf: func() []byte {
				buf := []byte{66, 0, 0, 0, 200} // Claims 200 bytes (will be capped by min())
				buf = append(buf, 0)            // Empty statement (index 5)
				buf = append(buf, 0)            // Empty portal (index 6)
				// Add format codes to fill exactly to position 126
				// We want ptr to be at 126 after processing formats, so ptr+2=128
				// which would try to read buf[126:128], the last 2 bytes
				// But size=128, so ptr+2 >= size triggers the error
				numFormats := (128 - 7 - 2 - 2) / 2 // 117 / 2 = 58 formats + 1 byte left
				buf = append(buf, byte(numFormats>>8), byte(numFormats))
				for i := 0; i < numFormats; i++ {
					buf = append(buf, 0, 0)
				}
				// Add padding to get to exactly 126
				if len(buf) < 126 {
					buf = append(buf, make([]byte, 126-len(buf))...)
				}
				// Trying to read params count at ptr=126 would access buf[126:128]
				// size=min(200,128)=128, so check 126+2>=128 is true, triggers error
				return buf
			}(),
			wantErr: "too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, portal, args, err := parsePostgresBindCommand(tt.buf)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantStatement, statement)
			assert.Equal(t, tt.wantPortal, portal)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}
