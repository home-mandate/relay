// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"errors"
	"testing"
)

func TestNegotiateVersion(t *testing.T) {
	tests := []struct {
		name                                 string
		peerMin, peerMax, localMin, localMax uint8
		want                                 uint8
		wantErr                              error
	}{
		{"identical single version", 1, 1, 1, 1, 1, nil},
		{"highest common version wins", 1, 3, 2, 4, 3, nil},
		{"local is N and N-1, peer only N-1", 1, 1, 1, 2, 1, nil},
		{"local is N and N-1, peer only N", 2, 2, 1, 2, 2, nil},
		{"peer newer than anything we know", 3, 5, 1, 2, 0, ErrUnsupportedVersion},
		{"peer older than anything we accept", 1, 1, 2, 3, 0, ErrUnsupportedVersion},
		{"peer min zero", 0, 1, 1, 1, 0, ErrMalformed},
		{"peer range inverted", 2, 1, 1, 2, 0, ErrMalformed},
		{"local range invalid", 1, 1, 2, 1, 0, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NegotiateVersion(VersionRange{tt.peerMin, tt.peerMax}, VersionRange{tt.localMin, tt.localMax})
			if !errors.Is(err, tt.wantErr) || got != tt.want {
				t.Fatalf("got %d, %v; want %d, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestIntersectCapabilities(t *testing.T) {
	tests := []struct {
		name      string
		offered   []Capability
		supported []Capability
		want      []Capability
	}{
		{"both empty", nil, nil, nil},
		{"nothing offered", nil, []Capability{1}, nil},
		{"nothing supported", []Capability{1}, nil, nil},
		{"partial overlap keeps ascending order", []Capability{1, 3, 5}, []Capability{3, 4, 5, 6}, []Capability{3, 5}},
		{"unknown capabilities are dropped", []Capability{9, 10}, []Capability{1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IntersectCapabilities(tt.offered, tt.supported)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}
