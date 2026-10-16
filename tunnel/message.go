// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// Core message types (specification section 4.2).
const (
	TypeHello       Type = 0x0001
	TypeHelloAck    Type = 0x0002
	TypePing        Type = 0x0003
	TypePong        Type = 0x0004
	TypeStreamOpen  Type = 0x0010
	TypeStreamClose Type = 0x0011
	TypeError       Type = 0x0012
	TypeDrain       Type = 0x0013
	TypeDataBind    Type = 0x0020
)

// Field limits (specification section 7).
const (
	MaxVersionString     = 64
	MaxCapabilities      = 16
	MaxErrorText         = 128
	MinHeartbeatSeconds  = 5
	MaxHeartbeatSeconds  = 120
	MaxPoolSize          = 16
	MaxStreams           = 256
	MaxDrainGraceSeconds = 600
)

var (
	// ErrMalformed marks any payload that violates the specification.
	ErrMalformed = errors.New("tunnel: malformed message")
	// ErrUnsupportedVersion is returned when the version ranges do not overlap.
	ErrUnsupportedVersion = errors.New("tunnel: no common protocol version")
	// ErrUnknownType is returned for a type the receiver must reject (core or extension class).
	ErrUnknownType = errors.New("tunnel: unknown message type")
	// ErrIgnorableType is returned for an unknown type with the high bit set: skip the frame.
	ErrIgnorableType = errors.New("tunnel: unknown optional message type")
	// ErrWrongDirection is returned for a message sent by the wrong role.
	ErrWrongDirection = errors.New("tunnel: message from the wrong sender")
	// ErrWrongChannel is returned for a message on the wrong kind of connection.
	ErrWrongChannel = errors.New("tunnel: message on the wrong connection")
	// ErrWrongPhase is returned for a message that is not allowed in the current phase of the
	// control connection, including every optional-range frame before the handshake completed.
	ErrWrongPhase = errors.New("tunnel: message not allowed in this phase")
)

func errMalformed(detail string) error { return fmt.Errorf("%w: %s", ErrMalformed, detail) }

// Sender says which role sent a control message.
type Sender uint8

// Roles.
const (
	FromGateway Sender = 1
	FromRelay   Sender = 2
)

// Capability is an optional feature negotiated in the handshake. Capability numbers are assigned
// in the specification; v1 defines none.
type Capability uint16

// Message is a control or data-bind message with a fixed wire form.
type Message interface {
	// Type returns the frame type.
	Type() Type
	validate() error
	appendPayload(dst []byte) []byte
}

// Hello is the gateway's first message on the control connection.
type Hello struct {
	MinVersion, MaxVersion uint8
	GatewayVersion         string
	Capabilities           []Capability
}

// HelloAck is the relay's answer: the chosen version and the limits that apply to the installation.
type HelloAck struct {
	Version          uint8
	RelayVersion     string
	HeartbeatSeconds uint16
	PoolSize         uint8
	MaxStreams       uint16
	Capabilities     []Capability
}

// Ping is a heartbeat probe; the peer answers with a Pong carrying the same nonce.
type Ping struct{ Nonce uint64 }

// Pong answers a Ping.
type Pong struct{ Nonce uint64 }

// StreamOpen is the relay's signal that an agent connection waits; the gateway dials a data
// connection and presents Token there.
type StreamOpen struct {
	Token       Token
	ValidMillis uint16
}

// CloseReason says why a stream signal ends.
type CloseReason uint8

// Close reasons.
const (
	CloseAgentGone CloseReason = 1
	CloseRefused   CloseReason = 2
	CloseTimeout   CloseReason = 3
	CloseInternal  CloseReason = 4
)

// StreamClose withdraws a signal (relay) or refuses it (gateway).
type StreamClose struct {
	Token  Token
	Reason CloseReason
}

// ErrorCode classifies a fatal control error.
type ErrorCode uint16

// Error codes. Receivers accept any non-zero code, so later codes do not break v1.
const (
	ErrCodeUnsupportedVersion ErrorCode = 1
	ErrCodeMalformed          ErrorCode = 2
	ErrCodeUnknownType        ErrorCode = 3
	ErrCodeLimitExceeded      ErrorCode = 4
	ErrCodeUnauthorized       ErrorCode = 5
	ErrCodeTimeout            ErrorCode = 6
	ErrCodeInternal           ErrorCode = 7
	ErrCodeSuperseded         ErrorCode = 8
	ErrCodeProtocol           ErrorCode = 9
	ErrCodeSessionExists      ErrorCode = 10
)

// ErrorMessage reports a fatal error; the sender closes the connection right after it.
type ErrorMessage struct {
	Code ErrorCode
	Text string
}

// DrainReason says why a peer wants to stop.
type DrainReason uint8

// Drain reasons.
const (
	DrainShutdown DrainReason = 1
	DrainRestart  DrainReason = 2
	DrainOverload DrainReason = 3
)

// Drain announces that no new streams should start; open streams may finish within the grace time.
type Drain struct {
	Reason       DrainReason
	GraceSeconds uint16
}

// DataBind is the first frame on a data connection: it presents the token from a StreamOpen.
type DataBind struct{ Token Token }

// Type implementations.

func (Hello) Type() Type        { return TypeHello }
func (HelloAck) Type() Type     { return TypeHelloAck }
func (Ping) Type() Type         { return TypePing }
func (Pong) Type() Type         { return TypePong }
func (StreamOpen) Type() Type   { return TypeStreamOpen }
func (StreamClose) Type() Type  { return TypeStreamClose }
func (ErrorMessage) Type() Type { return TypeError }
func (Drain) Type() Type        { return TypeDrain }
func (DataBind) Type() Type     { return TypeDataBind }

var typeNames = map[Type]string{
	TypeHello: "hello", TypeHelloAck: "hello-ack", TypePing: "ping", TypePong: "pong",
	TypeStreamOpen: "stream-open", TypeStreamClose: "stream-close", TypeError: "error",
	TypeDrain: "drain", TypeDataBind: "data-bind",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type 0x%04x", uint16(t))
}

// Validation.

func validString(s string, minLen, maxLen int) error {
	if len(s) < minLen || len(s) > maxLen {
		return errMalformed("string length")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return errMalformed("string is not printable ASCII")
		}
	}
	return nil
}

func validCapabilities(cs []Capability) error {
	if len(cs) > MaxCapabilities {
		return errMalformed("too many capabilities")
	}
	for i, c := range cs {
		if c == 0 || (i > 0 && c <= cs[i-1]) {
			return errMalformed("capabilities must be non-zero and strictly ascending")
		}
	}
	return nil
}

func (m Hello) validate() error {
	if m.MinVersion == 0 || m.MinVersion > m.MaxVersion {
		return errMalformed("version range")
	}
	if err := validString(m.GatewayVersion, 1, MaxVersionString); err != nil {
		return err
	}
	return validCapabilities(m.Capabilities)
}

func (m HelloAck) validate() error {
	switch {
	case m.Version == 0:
		return errMalformed("version")
	case m.HeartbeatSeconds < MinHeartbeatSeconds || m.HeartbeatSeconds > MaxHeartbeatSeconds:
		return errMalformed("heartbeat interval")
	case m.PoolSize > MaxPoolSize:
		return errMalformed("pool size")
	case m.MaxStreams == 0 || m.MaxStreams > MaxStreams:
		return errMalformed("stream limit")
	}
	if err := validString(m.RelayVersion, 1, MaxVersionString); err != nil {
		return err
	}
	return validCapabilities(m.Capabilities)
}

func (Ping) validate() error { return nil }
func (Pong) validate() error { return nil }

func (m StreamOpen) validate() error {
	if m.ValidMillis == 0 || m.ValidMillis > TokenValidityMillis {
		return errMalformed("token validity")
	}
	return nil
}

func (m StreamClose) validate() error {
	if m.Reason < CloseAgentGone || m.Reason > CloseInternal {
		return errMalformed("close reason")
	}
	return nil
}

func (m ErrorMessage) validate() error {
	if m.Code == 0 {
		return errMalformed("error code")
	}
	return validString(m.Text, 0, MaxErrorText)
}

func (m Drain) validate() error {
	if m.Reason < DrainShutdown || m.Reason > DrainOverload {
		return errMalformed("drain reason")
	}
	if m.GraceSeconds > MaxDrainGraceSeconds {
		return errMalformed("drain grace time")
	}
	return nil
}

func (DataBind) validate() error { return nil }

// Encoding. Every field has exactly one encoding, so decode followed by encode is the identity.

func appendString(dst []byte, s string) []byte { return append(append(dst, byte(len(s))), s...) }

func appendCaps(dst []byte, cs []Capability) []byte {
	dst = append(dst, byte(len(cs)))
	for _, c := range cs {
		dst = binary.BigEndian.AppendUint16(dst, uint16(c))
	}
	return dst
}

func (m Hello) appendPayload(dst []byte) []byte {
	dst = append(dst, m.MinVersion, m.MaxVersion)
	return appendCaps(appendString(dst, m.GatewayVersion), m.Capabilities)
}

func (m HelloAck) appendPayload(dst []byte) []byte {
	dst = appendString(append(dst, m.Version), m.RelayVersion)
	dst = binary.BigEndian.AppendUint16(dst, m.HeartbeatSeconds)
	dst = binary.BigEndian.AppendUint16(append(dst, m.PoolSize), m.MaxStreams)
	return appendCaps(dst, m.Capabilities)
}

func (m Ping) appendPayload(dst []byte) []byte { return binary.BigEndian.AppendUint64(dst, m.Nonce) }
func (m Pong) appendPayload(dst []byte) []byte { return binary.BigEndian.AppendUint64(dst, m.Nonce) }

func (m StreamOpen) appendPayload(dst []byte) []byte {
	return binary.BigEndian.AppendUint16(append(dst, m.Token[:]...), m.ValidMillis)
}

func (m StreamClose) appendPayload(dst []byte) []byte {
	return append(append(dst, m.Token[:]...), byte(m.Reason))
}

func (m ErrorMessage) appendPayload(dst []byte) []byte {
	return appendString(binary.BigEndian.AppendUint16(dst, uint16(m.Code)), m.Text)
}

func (m Drain) appendPayload(dst []byte) []byte {
	return binary.BigEndian.AppendUint16(append(dst, byte(m.Reason)), m.GraceSeconds)
}

func (m DataBind) appendPayload(dst []byte) []byte { return append(dst, m.Token[:]...) }

// EncodeMessage validates m and returns its complete frame.
func EncodeMessage(m Message) ([]byte, error) {
	if isNil(m) {
		return nil, errMalformed("nil message")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return AppendFrame(nil, Frame{Type: m.Type(), Payload: m.appendPayload(nil)})
}

// isNil reports a nil interface or an interface holding a nil pointer, on which the value
// receivers would panic.
func isNil(m Message) bool {
	if m == nil {
		return true
	}
	v := reflect.ValueOf(m)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// Decoding.

// reader consumes a payload and remembers the first shortfall.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *reader) str() string { return string(r.take(int(r.u8()))) }

func (r *reader) token() (t Token) {
	copy(t[:], r.take(TokenSize))
	return t
}

func (r *reader) caps() []Capability {
	n := int(r.u8())
	if n > MaxCapabilities {
		r.bad = true
		return nil
	}
	var cs []Capability
	for range n {
		cs = append(cs, Capability(r.u16()))
	}
	return cs
}

// finish reports truncation or trailing bytes.
func (r *reader) finish() error {
	if r.bad {
		return errMalformed("truncated payload")
	}
	if len(r.b) != 0 {
		return errMalformed("trailing bytes")
	}
	return nil
}

func decodeHello(r *reader) Message {
	return Hello{MinVersion: r.u8(), MaxVersion: r.u8(), GatewayVersion: r.str(), Capabilities: r.caps()}
}

func decodeHelloAck(r *reader) Message {
	m := HelloAck{Version: r.u8(), RelayVersion: r.str(), HeartbeatSeconds: r.u16()}
	m.PoolSize, m.MaxStreams, m.Capabilities = r.u8(), r.u16(), r.caps()
	return m
}

func decodeStreamOpen(r *reader) Message {
	return StreamOpen{Token: r.token(), ValidMillis: r.u16()}
}

func decodeStreamClose(r *reader) Message {
	return StreamClose{Token: r.token(), Reason: CloseReason(r.u8())}
}

func decodeError(r *reader) Message { return ErrorMessage{Code: ErrorCode(r.u16()), Text: r.str()} }
func decodeDrain(r *reader) Message {
	return Drain{Reason: DrainReason(r.u8()), GraceSeconds: r.u16()}
}

// controlTypes lists who may send which control message.
var controlTypes = map[Type]struct {
	senders []Sender
	decode  func(*reader) Message
}{
	TypeHello:       {[]Sender{FromGateway}, decodeHello},
	TypeHelloAck:    {[]Sender{FromRelay}, decodeHelloAck},
	TypePing:        {[]Sender{FromGateway, FromRelay}, func(r *reader) Message { return Ping{Nonce: r.u64()} }},
	TypePong:        {[]Sender{FromGateway, FromRelay}, func(r *reader) Message { return Pong{Nonce: r.u64()} }},
	TypeStreamOpen:  {[]Sender{FromRelay}, decodeStreamOpen},
	TypeStreamClose: {[]Sender{FromGateway, FromRelay}, decodeStreamClose},
	TypeError:       {[]Sender{FromGateway, FromRelay}, decodeError},
	TypeDrain:       {[]Sender{FromGateway, FromRelay}, decodeDrain},
}

// DecodeControl decodes a frame received on a control connection from the given sender.
//
// Unknown types follow the rule of specification section 4.2: an unknown type with the high bit
// set gives ErrIgnorableType (skip the frame, its payload was already bounded by MaxPayload);
// every other unknown type, including the whole extension range 0x0100-0x7FFF, gives
// ErrUnknownType (fatal). A DataBind on a control connection gives ErrWrongChannel.
func DecodeControl(from Sender, f Frame) (Message, error) {
	if f.Type == 0 {
		return nil, ErrInvalidType
	}
	if from != FromGateway && from != FromRelay {
		return nil, ErrWrongDirection
	}
	spec, ok := controlTypes[f.Type]
	if !ok {
		switch {
		case f.Type == TypeDataBind:
			return nil, ErrWrongChannel
		case f.Type.IsIgnorable():
			return nil, ErrIgnorableType
		}
		return nil, fmt.Errorf("%w: %v", ErrUnknownType, f.Type)
	}
	if !containsSender(spec.senders, from) {
		return nil, fmt.Errorf("%w: %v", ErrWrongDirection, f.Type)
	}
	r := &reader{b: f.Payload}
	m := spec.decode(r)
	if err := r.finish(); err != nil {
		return nil, fmt.Errorf("%v: %w", f.Type, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%v: %w", f.Type, err)
	}
	return m, nil
}

// Phase is the state of a control connection from the receiver's point of view.
type Phase uint8

// Phases.
const (
	// PhaseHandshake lasts until hello and hello-ack were exchanged.
	PhaseHandshake Phase = 1
	// PhaseEstablished follows the handshake.
	PhaseEstablished Phase = 2
)

// DecodeControlIn is DecodeControl with the phase rules of specification section 5.1: before the
// handshake completed only hello, hello-ack, ping, pong and error are valid and optional-range
// frames are refused; afterwards hello and hello-ack are refused. Extension types are always
// refused in v1 because no capability defines any; a later version enforces capability gating in
// this function's caller layer, which knows the negotiated capabilities.
func DecodeControlIn(phase Phase, from Sender, f Frame) (Message, error) {
	if phase != PhaseHandshake && phase != PhaseEstablished {
		return nil, ErrWrongPhase
	}
	if phase == PhaseHandshake && f.Type.IsIgnorable() {
		return nil, fmt.Errorf("%w: optional type before hello", ErrWrongPhase)
	}
	m, err := DecodeControl(from, f)
	if err != nil {
		return nil, err
	}
	switch m.Type() {
	case TypeHello, TypeHelloAck:
		if phase == PhaseEstablished {
			return nil, fmt.Errorf("%w: %v", ErrWrongPhase, m.Type())
		}
	case TypePing, TypePong, TypeError:
	default:
		if phase == PhaseHandshake {
			return nil, fmt.Errorf("%w: %v", ErrWrongPhase, m.Type())
		}
	}
	return m, nil
}

func containsSender(ss []Sender, s Sender) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// DecodeDataBind decodes the first frame of a data connection.
func DecodeDataBind(f Frame) (DataBind, error) {
	if f.Type != TypeDataBind {
		return DataBind{}, fmt.Errorf("%w: %v", ErrWrongChannel, f.Type)
	}
	r := &reader{b: f.Payload}
	m := DataBind{Token: r.token()}
	if err := r.finish(); err != nil {
		return DataBind{}, fmt.Errorf("%v: %w", f.Type, err)
	}
	return m, nil
}

// ReadDataBind reads the first frame of a data connection from r and decodes it. It reads at
// most HeaderSize+TokenSize bytes and refuses any larger announced payload from the header alone.
func ReadDataBind(r io.Reader) (DataBind, error) {
	f, err := ReadFrame(r, TokenSize)
	if err != nil {
		return DataBind{}, err
	}
	return DecodeDataBind(f)
}
