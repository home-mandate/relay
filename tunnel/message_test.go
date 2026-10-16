// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func tok(b byte) Token {
	var t Token
	for i := range t {
		t[i] = b
	}
	return t
}

func TestMessagesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		from Sender
		msg  Message
	}{
		{"hello", FromGateway, Hello{MinVersion: 1, MaxVersion: 2, GatewayVersion: "1.4.0-rc.1", Capabilities: []Capability{1, 7, 300}}},
		{"hello without capabilities", FromGateway, Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "x"}},
		{"hello acknowledgement", FromRelay, HelloAck{Version: 1, RelayVersion: "0.1.0", HeartbeatSeconds: 15, PoolSize: 4, MaxStreams: 64, Capabilities: []Capability{2}}},
		{"ping from gateway", FromGateway, Ping{Nonce: 1<<63 + 5}},
		{"ping from relay", FromRelay, Ping{Nonce: 0}},
		{"pong", FromRelay, Pong{Nonce: 42}},
		{"stream open", FromRelay, StreamOpen{Token: tok(0xAB), ValidMillis: TokenValidityMillis}},
		{"stream close by relay", FromRelay, StreamClose{Token: tok(1), Reason: CloseAgentGone}},
		{"stream close by gateway", FromGateway, StreamClose{Token: tok(2), Reason: CloseRefused}},
		{"error", FromRelay, ErrorMessage{Code: ErrCodeLimitExceeded, Text: "too many streams"}},
		{"error without text", FromGateway, ErrorMessage{Code: ErrCodeInternal}},
		{"drain from relay", FromRelay, Drain{Reason: DrainRestart, GraceSeconds: 600}},
		{"drain from gateway", FromGateway, Drain{Reason: DrainShutdown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			wire, err := EncodeMessage(tt.msg)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			f, n, err := DecodeFrame(wire)
			if err != nil || n != len(wire) {
				t.Fatalf("frame: n=%d err=%v", n, err)
			}

			// Act
			got, err := DecodeControl(tt.from, f)

			// Assert
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(normalize(got), normalize(tt.msg)) {
				t.Fatalf("got %#v, want %#v", got, tt.msg)
			}
		})
	}
}

// normalize turns empty capability slices into nil so DeepEqual compares meaning.
func normalize(m Message) Message {
	switch v := m.(type) {
	case Hello:
		if len(v.Capabilities) == 0 {
			v.Capabilities = nil
		}
		return v
	case HelloAck:
		if len(v.Capabilities) == 0 {
			v.Capabilities = nil
		}
		return v
	}
	return m
}

func TestEncodeMessageRejectsInvalidMessages(t *testing.T) {
	long := strings.Repeat("a", MaxVersionString+1)
	tests := []struct {
		name string
		msg  Message
	}{
		{"hello min zero", Hello{MinVersion: 0, MaxVersion: 1, GatewayVersion: "v"}},
		{"hello min above max", Hello{MinVersion: 3, MaxVersion: 2, GatewayVersion: "v"}},
		{"hello empty version string", Hello{MinVersion: 1, MaxVersion: 1}},
		{"hello long version string", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: long}},
		{"hello non-printable version string", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "a\nb"}},
		{"hello non-ASCII version string", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "vä"}},
		{"hello too many capabilities", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "v", Capabilities: make([]Capability, MaxCapabilities+1)}},
		{"hello capabilities not ascending", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "v", Capabilities: []Capability{2, 1}}},
		{"hello duplicate capabilities", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "v", Capabilities: []Capability{1, 1}}},
		{"hello capability zero", Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "v", Capabilities: []Capability{0}}},
		{"ack version zero", HelloAck{RelayVersion: "r", HeartbeatSeconds: 15, PoolSize: 1, MaxStreams: 1}},
		{"ack heartbeat too small", HelloAck{Version: 1, RelayVersion: "r", HeartbeatSeconds: MinHeartbeatSeconds - 1, PoolSize: 1, MaxStreams: 1}},
		{"ack heartbeat too large", HelloAck{Version: 1, RelayVersion: "r", HeartbeatSeconds: MaxHeartbeatSeconds + 1, PoolSize: 1, MaxStreams: 1}},
		{"ack pool too large", HelloAck{Version: 1, RelayVersion: "r", HeartbeatSeconds: 15, PoolSize: MaxPoolSize + 1, MaxStreams: 1}},
		{"ack no streams", HelloAck{Version: 1, RelayVersion: "r", HeartbeatSeconds: 15, PoolSize: 1}},
		{"ack too many streams", HelloAck{Version: 1, RelayVersion: "r", HeartbeatSeconds: 15, PoolSize: 1, MaxStreams: MaxStreams + 1}},
		{"ack empty relay version", HelloAck{Version: 1, HeartbeatSeconds: 15, PoolSize: 1, MaxStreams: 1}},
		{"stream open zero validity", StreamOpen{Token: tok(1)}},
		{"stream open validity above the limit", StreamOpen{Token: tok(1), ValidMillis: TokenValidityMillis + 1}},
		{"stream close reason zero", StreamClose{Token: tok(1)}},
		{"stream close unknown reason", StreamClose{Token: tok(1), Reason: 99}},
		{"error code zero", ErrorMessage{Text: "x"}},
		{"error long text", ErrorMessage{Code: 1, Text: strings.Repeat("a", MaxErrorText+1)}},
		{"error control character", ErrorMessage{Code: 1, Text: "a\x00"}},
		{"drain reason zero", Drain{}},
		{"drain grace too long", Drain{Reason: DrainRestart, GraceSeconds: MaxDrainGraceSeconds + 1}},
		{"nil message", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeMessage(tt.msg)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestDecodeControlRejectsMalformedPayloads(t *testing.T) {
	validHello := []byte{1, 1, 1, 'v', 0}
	tests := []struct {
		name string
		typ  Type
		from Sender
		in   []byte
	}{
		{"hello empty payload", TypeHello, FromGateway, nil},
		{"hello trailing byte", TypeHello, FromGateway, append(append([]byte{}, validHello...), 0)},
		{"hello truncated string", TypeHello, FromGateway, []byte{1, 1, 5, 'v', 0}},
		{"hello zero-length string", TypeHello, FromGateway, []byte{1, 1, 0, 0}},
		{"hello version range inverted", TypeHello, FromGateway, []byte{2, 1, 1, 'v', 0}},
		{"hello version zero", TypeHello, FromGateway, []byte{0, 1, 1, 'v', 0}},
		{"hello capability count beyond the payload", TypeHello, FromGateway, []byte{1, 1, 1, 'v', 3, 0, 1}},
		{"hello capability count over the limit", TypeHello, FromGateway, append([]byte{1, 1, 1, 'v', MaxCapabilities + 1}, make([]byte, 2*(MaxCapabilities+1))...)},
		{"hello capabilities descending", TypeHello, FromGateway, []byte{1, 1, 1, 'v', 2, 0, 2, 0, 1}},
		{"hello control character", TypeHello, FromGateway, []byte{1, 1, 1, 0x07, 0}},
		{"ack truncated", TypeHelloAck, FromRelay, []byte{1, 1, 'r'}},
		{"ack trailing byte", TypeHelloAck, FromRelay, []byte{1, 1, 'r', 0, 15, 1, 0, 1, 0, 9}},
		{"ack heartbeat zero", TypeHelloAck, FromRelay, []byte{1, 1, 'r', 0, 0, 1, 0, 1, 0}},
		{"ack pool too large", TypeHelloAck, FromRelay, []byte{1, 1, 'r', 0, 15, MaxPoolSize + 1, 0, 1, 0}},
		{"ack streams zero", TypeHelloAck, FromRelay, []byte{1, 1, 'r', 0, 15, 1, 0, 0, 0}},
		{"ping short", TypePing, FromGateway, make([]byte, 7)},
		{"ping long", TypePing, FromRelay, make([]byte, 9)},
		{"pong short", TypePong, FromGateway, nil},
		{"stream open short", TypeStreamOpen, FromRelay, make([]byte, TokenSize)},
		{"stream open long", TypeStreamOpen, FromRelay, make([]byte, TokenSize+3)},
		{"stream open validity zero", TypeStreamOpen, FromRelay, make([]byte, TokenSize+2)},
		{"stream close short", TypeStreamClose, FromRelay, make([]byte, TokenSize)},
		{"stream close reason zero", TypeStreamClose, FromGateway, make([]byte, TokenSize+1)},
		{"error short", TypeError, FromRelay, []byte{0}},
		{"error code zero", TypeError, FromRelay, []byte{0, 0, 0}},
		{"error text length beyond payload", TypeError, FromRelay, []byte{0, 1, 4, 'a'}},
		{"error trailing", TypeError, FromRelay, []byte{0, 1, 0, 'a'}},
		{"drain short", TypeDrain, FromRelay, []byte{1, 0}},
		{"drain reason zero", TypeDrain, FromRelay, []byte{0, 0, 1}},
		{"drain grace too long", TypeDrain, FromRelay, []byte{1, 0xFF, 0xFF}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeControl(tt.from, Frame{Type: tt.typ, Payload: tt.in})
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestDecodeControlTypeAndDirectionRules(t *testing.T) {
	tests := []struct {
		name string
		typ  Type
		from Sender
		want error
	}{
		{"hello from relay", TypeHello, FromRelay, ErrWrongDirection},
		{"ack from gateway", TypeHelloAck, FromGateway, ErrWrongDirection},
		{"stream open from gateway", TypeStreamOpen, FromGateway, ErrWrongDirection},
		{"data bind on the control connection", TypeDataBind, FromGateway, ErrWrongChannel},
		{"unassigned core type", 0x0005, FromRelay, ErrUnknownType},
		{"unassigned core type at the top of the range", 0x00FF, FromGateway, ErrUnknownType},
		{"extension type that was not negotiated", 0x0101, FromGateway, ErrUnknownType},
		{"extension type at the top of the range", 0x7FFF, FromRelay, ErrUnknownType},
		{"optional type is ignorable", 0x8000, FromGateway, ErrIgnorableType},
		{"optional type at the top is ignorable", 0xFFFF, FromRelay, ErrIgnorableType},
		{"type zero", 0, FromGateway, ErrInvalidType},
		{"unknown sender", TypePing, Sender(9), ErrWrongDirection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeControl(tt.from, Frame{Type: tt.typ, Payload: make([]byte, 8)})
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUnknownOptionalTypeIsIgnoredWithoutInspectingThePayload(t *testing.T) {
	_, err := DecodeControl(FromGateway, Frame{Type: 0x8123, Payload: bytes.Repeat([]byte{0xFF}, MaxPayload)})
	if !errors.Is(err, ErrIgnorableType) {
		t.Fatalf("err = %v", err)
	}
}

func TestDataBindRoundTripAndRejections(t *testing.T) {
	t.Run("round trip through ReadDataBind", func(t *testing.T) {
		wire, err := EncodeMessage(DataBind{Token: tok(7)})
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadDataBind(bytes.NewReader(wire))
		if err != nil || got.Token != tok(7) {
			t.Fatalf("got %v, err %v", got, err)
		}
	})
	t.Run("does not read past the frame", func(t *testing.T) {
		wire, _ := EncodeMessage(DataBind{Token: tok(7)})
		r := bytes.NewReader(append(wire, 0xEE))
		if _, err := ReadDataBind(r); err != nil {
			t.Fatal(err)
		}
		if r.Len() != 1 {
			t.Fatalf("left %d bytes, want 1", r.Len())
		}
	})
	t.Run("oversized frame is refused from the header alone", func(t *testing.T) {
		in := []byte{0, byte(TypeDataBind), 0, TokenSize + 1}
		if _, err := ReadDataBind(bytes.NewReader(in)); !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("other frame types", func(t *testing.T) {
		wire, _ := EncodeMessage(Ping{Nonce: 1})
		if _, err := ReadDataBind(bytes.NewReader(wire)); !errors.Is(err, ErrWrongChannel) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("short token", func(t *testing.T) {
		if _, err := DecodeDataBind(Frame{Type: TypeDataBind, Payload: make([]byte, TokenSize-1)}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("truncated stream", func(t *testing.T) {
		if _, err := ReadDataBind(bytes.NewReader([]byte{0, byte(TypeDataBind), 0, TokenSize, 1})); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("type is TypeDataBind", func(t *testing.T) {
		if got := (DataBind{}).Type(); got != TypeDataBind {
			t.Fatalf("type = %v", got)
		}
	})
}

func TestTypeString(t *testing.T) {
	if TypeHello.String() != "hello" || Type(0x0123).String() != "type 0x0123" {
		t.Fatalf("%q %q", TypeHello.String(), Type(0x0123).String())
	}
	for _, ty := range []Type{TypeHello, TypeHelloAck, TypePing, TypePong, TypeStreamOpen, TypeStreamClose, TypeError, TypeDrain, TypeDataBind} {
		if strings.HasPrefix(ty.String(), "type ") {
			t.Errorf("type %d has no name", ty)
		}
	}
}

func TestMessageTypes(t *testing.T) {
	want := map[Type]Message{
		TypeHello: Hello{}, TypeHelloAck: HelloAck{}, TypePing: Ping{}, TypePong: Pong{},
		TypeStreamOpen: StreamOpen{}, TypeStreamClose: StreamClose{}, TypeError: ErrorMessage{},
		TypeDrain: Drain{}, TypeDataBind: DataBind{},
	}
	for typ, m := range want {
		if m.Type() != typ {
			t.Errorf("%T.Type() = %v, want %v", m, m.Type(), typ)
		}
	}
}

func FuzzDecodeControl(f *testing.F) {
	seeds := []Message{
		Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "1.0.0", Capabilities: []Capability{1, 2}},
		HelloAck{Version: 1, RelayVersion: "0.1", HeartbeatSeconds: 15, PoolSize: 4, MaxStreams: 64},
		Ping{Nonce: 1}, Pong{Nonce: 2}, StreamOpen{Token: tok(3), ValidMillis: 10000},
		StreamClose{Token: tok(4), Reason: CloseAgentGone}, ErrorMessage{Code: 2, Text: "bad"},
		Drain{Reason: DrainRestart, GraceSeconds: 30},
	}
	for _, m := range seeds {
		wire, err := EncodeMessage(m)
		if err != nil {
			f.Fatal(err)
		}
		fr, _, _ := DecodeFrame(wire)
		f.Add(uint16(fr.Type), fr.Payload, uint8(FromGateway))
		f.Add(uint16(fr.Type), fr.Payload, uint8(FromRelay))
	}
	f.Add(uint16(0x8001), []byte{1, 2, 3}, uint8(FromRelay))
	f.Add(uint16(0), []byte(nil), uint8(0))
	f.Fuzz(func(t *testing.T, typ uint16, payload []byte, from uint8) {
		if len(payload) > MaxPayload {
			return
		}
		m, err := DecodeControl(Sender(from), Frame{Type: Type(typ), Payload: payload})
		if err != nil {
			return
		}
		// Whatever decodes must encode again to exactly the same bytes (canonical form).
		wire, err := EncodeMessage(m)
		if err != nil {
			t.Fatalf("decoded message does not encode: %v", err)
		}
		fr, _, err := DecodeFrame(wire)
		if err != nil || fr.Type != Type(typ) || !bytes.Equal(fr.Payload, payload) {
			t.Fatalf("not canonical: type %#x payload % x -> % x (%v)", typ, payload, fr.Payload, err)
		}
	})
}

func FuzzDecodeDataBind(f *testing.F) {
	wire, _ := EncodeMessage(DataBind{Token: tok(9)})
	f.Add(wire)
	f.Add(wire[:10])
	f.Add([]byte{0, 0x20, 0, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		b, err := ReadDataBind(r)
		if err != nil {
			return
		}
		if len(in)-r.Len() != HeaderSize+TokenSize || !bytes.Equal(in[HeaderSize:HeaderSize+TokenSize], b.Token[:]) {
			t.Fatalf("consumed %d bytes", len(in)-r.Len())
		}
	})
}

func TestEncodeMessageRejectsTypedNilPointers(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{"hello", (*Hello)(nil)},
		{"hello ack", (*HelloAck)(nil)},
		{"stream open", (*StreamOpen)(nil)},
		{"data bind", (*DataBind)(nil)},
		{"error message", (*ErrorMessage)(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeMessage(tt.msg)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("non-nil pointer works", func(t *testing.T) {
		if _, err := EncodeMessage(&Ping{Nonce: 1}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDecodeControlInPhase(t *testing.T) {
	hello, _ := EncodeMessage(Hello{MinVersion: 1, MaxVersion: 1, GatewayVersion: "v"})
	hf, _, _ := DecodeFrame(hello)
	open, _ := EncodeMessage(StreamOpen{Token: tok(1), ValidMillis: 1000})
	of, _, _ := DecodeFrame(open)
	ping, _ := EncodeMessage(Ping{Nonce: 3})
	pf, _, _ := DecodeFrame(ping)
	optional := Frame{Type: 0x8001, Payload: []byte{1}}

	tests := []struct {
		name  string
		phase Phase
		from  Sender
		f     Frame
		want  error
	}{
		{"hello during the handshake", PhaseHandshake, FromGateway, hf, nil},
		{"ping during the handshake", PhaseHandshake, FromGateway, pf, nil},
		{"stream open before hello-ack", PhaseHandshake, FromRelay, of, ErrWrongPhase},
		{"optional type before hello", PhaseHandshake, FromGateway, optional, ErrWrongPhase},
		{"optional type after hello is ignorable", PhaseEstablished, FromGateway, optional, ErrIgnorableType},
		{"stream open once established", PhaseEstablished, FromRelay, of, nil},
		{"hello again once established", PhaseEstablished, FromGateway, hf, ErrWrongPhase},
		{"unknown phase", Phase(9), FromGateway, pf, ErrWrongPhase},
		{"unknown type in handshake", PhaseHandshake, FromGateway, Frame{Type: 0x0101}, ErrUnknownType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeControlIn(tt.phase, tt.from, tt.f)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
