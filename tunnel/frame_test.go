// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAppendFrameEncodesHeaderAndPayload(t *testing.T) {
	// Arrange
	f := Frame{Type: 0x0003, Payload: []byte{1, 2, 3}}

	// Act
	got, err := AppendFrame([]byte{0xAA}, f)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0xAA, 0x00, 0x03, 0x00, 0x03, 1, 2, 3}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestAppendFrameRejectsInvalidFrames(t *testing.T) {
	tests := []struct {
		name string
		f    Frame
		want error
	}{
		{"type zero", Frame{Type: 0}, ErrInvalidType},
		{"payload one over the limit", Frame{Type: 1, Payload: make([]byte, MaxPayload+1)}, ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AppendFrame(nil, tt.f)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAppendFrameAcceptsMaximumPayload(t *testing.T) {
	got, err := AppendFrame(nil, Frame{Type: 1, Payload: make([]byte, MaxPayload)})
	if err != nil || len(got) != HeaderSize+MaxPayload {
		t.Fatalf("len = %d, err = %v", len(got), err)
	}
}

func TestDecodeFrame(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		want     Frame
		wantUsed int
		wantErr  error
	}{
		{"empty payload", []byte{0, 1, 0, 0}, Frame{Type: 1, Payload: []byte{}}, 4, nil},
		{"payload and trailing bytes untouched", []byte{0x80, 0x01, 0, 2, 9, 8, 7}, Frame{Type: 0x8001, Payload: []byte{9, 8}}, 6, nil},
		{"nil input", nil, Frame{}, 0, ErrShortBuffer},
		{"short header", []byte{0, 1, 0}, Frame{}, 0, ErrShortBuffer},
		{"short payload", []byte{0, 1, 0, 3, 1, 2}, Frame{}, 0, ErrShortBuffer},
		{"type zero", []byte{0, 0, 0, 0}, Frame{}, 0, ErrInvalidType},
		{"length over the limit is rejected before the payload arrives", []byte{0, 1, 0x04, 0x01}, Frame{}, 0, ErrPayloadTooLarge},
		{"length 0xFFFF", []byte{0, 1, 0xFF, 0xFF}, Frame{}, 0, ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, used, err := DecodeFrame(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Type != tt.want.Type || !bytes.Equal(got.Payload, tt.want.Payload) || used != tt.wantUsed {
				t.Fatalf("got %+v used %d, want %+v used %d", got, used, tt.want, tt.wantUsed)
			}
		})
	}
}

func TestDecodeFrameCopiesThePayload(t *testing.T) {
	in := []byte{0, 1, 0, 1, 7}
	f, _, err := DecodeFrame(in)
	if err != nil {
		t.Fatal(err)
	}
	in[4] = 0
	if f.Payload[0] != 7 {
		t.Fatal("payload aliases the input buffer")
	}
}

func TestReadFrame(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		max     int
		want    Frame
		wantErr error
	}{
		{"complete frame", []byte{0, 2, 0, 2, 5, 6}, MaxPayload, Frame{Type: 2, Payload: []byte{5, 6}}, nil},
		{"clean end of stream", nil, MaxPayload, Frame{}, io.EOF},
		{"truncated header", []byte{0, 2}, MaxPayload, Frame{}, io.ErrUnexpectedEOF},
		{"truncated payload", []byte{0, 2, 0, 4, 1}, MaxPayload, Frame{}, io.ErrUnexpectedEOF},
		{"type zero", []byte{0, 0, 0, 0}, MaxPayload, Frame{}, ErrInvalidType},
		{"over the caller's limit", []byte{0, 2, 0, 5, 1, 2, 3, 4, 5}, 4, Frame{}, ErrPayloadTooLarge},
		{"caller limit above the protocol limit is clamped", []byte{0, 2, 0xFF, 0xFF}, 1 << 20, Frame{}, ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFrame(bytes.NewReader(tt.in), tt.max)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && (got.Type != tt.want.Type || !bytes.Equal(got.Payload, tt.want.Payload)) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadFrameConsumesExactlyOneFrame(t *testing.T) {
	r := bytes.NewReader([]byte{0, 1, 0, 1, 9, 0xDE, 0xAD})

	if _, err := ReadFrame(r, MaxPayload); err != nil {
		t.Fatal(err)
	}

	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, []byte{0xDE, 0xAD}) {
		t.Fatalf("rest = % x", rest)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteFrame(t *testing.T) {
	t.Run("writes header and payload in one call", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, Frame{Type: 9, Payload: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), []byte{0, 9, 0, 1, 1}) {
			t.Fatalf("got % x", buf.Bytes())
		}
	})
	t.Run("propagates writer errors", func(t *testing.T) {
		boom := errors.New("boom")
		if err := WriteFrame(failingWriter{boom}, Frame{Type: 9}); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rejects an invalid frame before writing", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, Frame{Type: 0}); !errors.Is(err, ErrInvalidType) || buf.Len() != 0 {
			t.Fatalf("err = %v, written %d", err, buf.Len())
		}
	})
}

func TestTypeClasses(t *testing.T) {
	tests := []struct {
		t                          Type
		core, extension, ignorable bool
	}{
		{0x0001, true, false, false},
		{0x00FF, true, false, false},
		{0x0100, false, true, false},
		{0x7FFF, false, true, false},
		{0x8000, false, false, true},
		{0xFFFF, false, false, true},
		{0x0000, false, false, false},
	}
	for _, tt := range tests {
		if tt.t.IsCore() != tt.core || tt.t.IsExtension() != tt.extension || tt.t.IsIgnorable() != tt.ignorable {
			t.Errorf("type %#04x: core=%v ext=%v ign=%v", uint16(tt.t), tt.t.IsCore(), tt.t.IsExtension(), tt.t.IsIgnorable())
		}
	}
}

func FuzzDecodeFrame(f *testing.F) {
	for _, s := range [][]byte{
		nil, {0, 1, 0, 0}, {0, 1, 0, 3, 1, 2, 3}, {0x80, 1, 0, 1, 9}, {0, 0, 0, 0}, {0, 1, 0xFF, 0xFF},
		bytes.Repeat([]byte{0xFF}, 64),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		fr, n, err := DecodeFrame(in)
		if err != nil {
			return
		}
		if n != HeaderSize+len(fr.Payload) || n > len(in) || len(fr.Payload) > MaxPayload || fr.Type == 0 {
			t.Fatalf("inconsistent result: n=%d len=%d type=%d", n, len(fr.Payload), fr.Type)
		}
		again, err := AppendFrame(nil, fr)
		if err != nil || !bytes.Equal(again, in[:n]) {
			t.Fatalf("re-encode differs: %v", err)
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	for _, s := range [][]byte{nil, {0, 1, 0, 0}, {0, 1, 0, 2, 1}, {0, 1, 0, 2, 1, 2, 3}} {
		f.Add(s, 32)
	}
	f.Fuzz(func(t *testing.T, in []byte, max int) {
		r := bytes.NewReader(in)
		fr, err := ReadFrame(r, max)
		if err != nil {
			return
		}
		if len(fr.Payload) > MaxPayload || (max >= 0 && len(fr.Payload) > max) {
			t.Fatalf("payload %d exceeds limit %d", len(fr.Payload), max)
		}
	})
}
