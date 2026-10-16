// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Framing limits (specification section 4.1).
const (
	// HeaderSize is the size of the frame header: type (2 bytes) and payload length (2 bytes).
	HeaderSize = 4
	// MaxPayload is the largest payload of any frame on any connection.
	MaxPayload = 1024
)

var (
	// ErrInvalidType is returned for frame type 0, which is reserved.
	ErrInvalidType = errors.New("tunnel: invalid frame type 0")
	// ErrPayloadTooLarge is returned when a frame announces more payload than allowed.
	ErrPayloadTooLarge = errors.New("tunnel: frame payload too large")
	// ErrShortBuffer is returned when the input ends before a complete frame.
	ErrShortBuffer = errors.New("tunnel: incomplete input")
)

// Type is the frame type. The number space is split into classes (specification section 4.2).
type Type uint16

// Type classes.
const (
	coreMax          Type = 0x00FF
	extensionMin     Type = 0x0100
	extensionMax     Type = 0x7FFF
	ignorableFlagBit Type = 0x8000
)

// IsCore reports whether t is in the core range 0x0001-0x00FF. Unassigned core types are errors.
func (t Type) IsCore() bool { return t >= 1 && t <= coreMax }

// IsExtension reports whether t is in the capability-gated range 0x0100-0x7FFF. Receivers reject
// these types unless the capability that defines them was negotiated.
func (t Type) IsExtension() bool { return t >= extensionMin && t <= extensionMax }

// IsIgnorable reports whether t has the high bit set: an unknown type of this class is skipped.
func (t Type) IsIgnorable() bool { return t&ignorableFlagBit != 0 }

// Frame is one length-prefixed message: a type and an opaque payload.
type Frame struct {
	Type    Type
	Payload []byte
}

// AppendFrame appends the wire form of f to dst.
func AppendFrame(dst []byte, f Frame) ([]byte, error) {
	if f.Type == 0 {
		return nil, ErrInvalidType
	}
	if len(f.Payload) > MaxPayload {
		return nil, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(f.Payload))
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(f.Type))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(f.Payload)))
	return append(dst, f.Payload...), nil
}

// parseHeader validates a header against maxPayload and returns the type and payload length.
func parseHeader(h []byte, maxPayload int) (Type, int, error) {
	t := Type(binary.BigEndian.Uint16(h[0:2]))
	n := int(binary.BigEndian.Uint16(h[2:4]))
	if t == 0 {
		return 0, 0, ErrInvalidType
	}
	if n > maxPayload {
		return 0, 0, fmt.Errorf("%w: %d bytes announced, limit %d", ErrPayloadTooLarge, n, maxPayload)
	}
	return t, n, nil
}

// DecodeFrame decodes the first frame of b and returns it with the number of bytes used. The
// payload is a copy. A frame announcing more than MaxPayload is refused from its header alone.
func DecodeFrame(b []byte) (Frame, int, error) {
	if len(b) < HeaderSize {
		return Frame{}, 0, ErrShortBuffer
	}
	t, n, err := parseHeader(b, MaxPayload)
	if err != nil {
		return Frame{}, 0, err
	}
	if len(b) < HeaderSize+n {
		return Frame{}, 0, ErrShortBuffer
	}
	return Frame{Type: t, Payload: append([]byte{}, b[HeaderSize:HeaderSize+n]...)}, HeaderSize + n, nil
}

// ReadFrame reads exactly one frame from r. maxPayload is clamped to [0, MaxPayload]; a frame
// announcing more is refused after its four header bytes, before any payload is read or
// allocated. It returns io.EOF only if r ended before the first byte and io.ErrUnexpectedEOF if
// it ended inside a frame. Callers must set read deadlines on the connection.
//
// After ANY error other than a clean io.EOF at a frame boundary the byte position is lost: the
// caller MUST close the connection and MUST NOT read another frame from it.
func ReadFrame(r io.Reader, maxPayload int) (Frame, error) {
	maxPayload = min(max(maxPayload, 0), MaxPayload)
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	t, n, err := parseHeader(h[:], maxPayload)
	if err != nil {
		return Frame{}, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return Frame{Type: t, Payload: payload}, nil
}

// WriteFrame writes f to w with a single Write call.
func WriteFrame(w io.Writer, f Frame) error {
	b, err := AppendFrame(make([]byte, 0, HeaderSize+len(f.Payload)), f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
