// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package handlers

import (
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
	"net"
)

func init() {
	RegisterHandler(Enums.PACKET_RESOLVER_LIST_RESPONSE, handleResolverListResponse)
}

func handleResolverListResponse(c ClientContext, packet VpnProto.Packet, addr *net.UDPAddr) error {
	return c.HandleResolverList(packet)
}
