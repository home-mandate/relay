// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import "slices"

// Protocol versions this package speaks. The relay supports the current version N and N-1; with
// only version 1 existing, both bounds are 1.
const (
	MinSupportedVersion uint8 = 1
	MaxSupportedVersion uint8 = 1
)

// VersionRange is an inclusive range of protocol versions.
type VersionRange struct{ Min, Max uint8 }

func (r VersionRange) valid() bool { return r.Min != 0 && r.Min <= r.Max }

// NegotiateVersion returns the highest version in both ranges. A range with Min 0 or Min above
// Max is malformed; ranges that do not overlap give ErrUnsupportedVersion.
func NegotiateVersion(peer, local VersionRange) (uint8, error) {
	if !peer.valid() || !local.valid() {
		return 0, errMalformed("version range")
	}
	lo, hi := max(peer.Min, local.Min), min(peer.Max, local.Max)
	if lo > hi {
		return 0, ErrUnsupportedVersion
	}
	return hi, nil
}

// IntersectCapabilities returns the capabilities in both lists, in ascending order. Offered
// capabilities that are not supported are dropped, never echoed.
func IntersectCapabilities(offered, supported []Capability) []Capability {
	var out []Capability
	for _, c := range offered {
		if slices.Contains(supported, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
