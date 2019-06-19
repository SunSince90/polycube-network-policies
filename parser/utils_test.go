package parser

import (
	"testing"

	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycubenetwork.com/v1beta"

	"github.com/stretchr/testify/assert"
)

func TestBuildIngress(t *testing.T) {
	src := "10.10.10.10"

	// --- First case: forward
	result := buildIngressConnectionTemplates(src, "forward", []v1beta.PolycubeNetworkPolicyProtocolContainer{})

	assert.Len(t, result.Ingress, 1)
	assert.Len(t, result.Egress, 2)

	for _, rule := range result.Egress {
		assert.Equal(t, src, rule.Src)
		assert.Equal(t, "forward", rule.Action)
	}
	assert.Equal(t, "new", result.Egress[0].Conntrack)
	assert.Equal(t, "established", result.Egress[1].Conntrack)

	for _, rule := range result.Ingress {
		assert.Equal(t, src, rule.Dst)
		assert.Equal(t, "established", rule.Conntrack)
		assert.Equal(t, "forward", rule.Action)
	}

	//	--- Second case: drop
	result = buildIngressConnectionTemplates(src, "drop", []v1beta.PolycubeNetworkPolicyProtocolContainer{})

	assert.Empty(t, result.Ingress)
	assert.Len(t, result.Egress, 1)

	assert.Equal(t, "drop", result.Egress[0].Action)
	assert.Equal(t, src, result.Egress[0].Src)
	assert.Equal(t, "new", result.Egress[0].Conntrack)

	//	--- Third case: with protocols
	tcpSource := int32(10)
	tcpDest := int32(80)
	udpSource := int32(100)
	udpDest := int32(800)
	protocols := []v1beta.PolycubeNetworkPolicyProtocolContainer{
		v1beta.PolycubeNetworkPolicyProtocolContainer{
			Protocol: v1beta.TCP,
			Ports: v1beta.PolycubeNetworkPolicyPorts{
				Source:      tcpSource,
				Destination: tcpDest,
			},
		},
		v1beta.PolycubeNetworkPolicyProtocolContainer{
			Protocol: v1beta.UDP,
			Ports: v1beta.PolycubeNetworkPolicyPorts{
				Source:      udpSource,
				Destination: udpDest,
			},
		},
	}

	result = buildIngressConnectionTemplates(src, "forward", protocols)

	assert.Len(t, result.Egress, len(protocols)*2)
	assert.Len(t, result.Ingress, len(protocols))

	for _, rule := range result.Egress {
		if rule.L4proto != "udp" && rule.L4proto != "tcp" {
			assert.FailNow(t, "unrecognized protocol", rule.L4proto)
		}
		if rule.L4proto == "tcp" {
			assert.Equal(t, tcpSource, rule.Sport)
			assert.Equal(t, tcpDest, rule.Dport)
		}
		if rule.L4proto == "udp" {
			assert.Equal(t, udpSource, rule.Sport)
			assert.Equal(t, udpDest, rule.Dport)
		}
	}

	for _, rule := range result.Ingress {
		if rule.L4proto != "udp" && rule.L4proto != "tcp" {
			assert.FailNow(t, "unrecognized protocol", rule.L4proto)
		}
		if rule.L4proto == "tcp" {
			assert.Equal(t, tcpDest, rule.Sport)
			assert.Equal(t, tcpSource, rule.Dport)
		}
		if rule.L4proto == "udp" {
			assert.Equal(t, udpDest, rule.Sport)
			assert.Equal(t, udpSource, rule.Dport)
		}
	}
}

func TestBuildEgress(t *testing.T) {
	dst := "10.10.10.10"

	// --- First case: forward
	result := buildEgressConnectionTemplates(dst, "forward", []v1beta.PolycubeNetworkPolicyProtocolContainer{})

	assert.Len(t, result.Egress, 1)
	assert.Len(t, result.Ingress, 2)

	for _, rule := range result.Ingress {
		assert.Equal(t, dst, rule.Dst)
		assert.Equal(t, "forward", rule.Action)
	}
	assert.Equal(t, "new", result.Ingress[0].Conntrack)
	assert.Equal(t, "established", result.Ingress[1].Conntrack)

	for _, rule := range result.Egress {
		assert.Equal(t, dst, rule.Src)
		assert.Equal(t, "established", rule.Conntrack)
		assert.Equal(t, "forward", rule.Action)
	}

	//	--- Second case: drop
	result = buildEgressConnectionTemplates(dst, "drop", []v1beta.PolycubeNetworkPolicyProtocolContainer{})

	assert.Empty(t, result.Egress)
	assert.Len(t, result.Ingress, 1)

	assert.Equal(t, "drop", result.Ingress[0].Action)
	assert.Equal(t, dst, result.Ingress[0].Dst)
	assert.Equal(t, "new", result.Ingress[0].Conntrack)

	//	--- Third case: with protocols
	tcpSource := int32(10)
	tcpDest := int32(80)
	udpSource := int32(100)
	udpDest := int32(800)
	protocols := []v1beta.PolycubeNetworkPolicyProtocolContainer{
		v1beta.PolycubeNetworkPolicyProtocolContainer{
			Protocol: v1beta.TCP,
			Ports: v1beta.PolycubeNetworkPolicyPorts{
				Source:      tcpSource,
				Destination: tcpDest,
			},
		},
		v1beta.PolycubeNetworkPolicyProtocolContainer{
			Protocol: v1beta.UDP,
			Ports: v1beta.PolycubeNetworkPolicyPorts{
				Source:      udpSource,
				Destination: udpDest,
			},
		},
	}

	result = buildEgressConnectionTemplates(dst, "forward", protocols)

	assert.Len(t, result.Ingress, len(protocols)*2)
	assert.Len(t, result.Egress, len(protocols))

	for _, rule := range result.Ingress {
		if rule.L4proto != "udp" && rule.L4proto != "tcp" {
			assert.FailNow(t, "unrecognized protocol", rule.L4proto)
		}
		if rule.L4proto == "tcp" {
			assert.Equal(t, tcpSource, rule.Sport)
			assert.Equal(t, tcpDest, rule.Dport)
		}
		if rule.L4proto == "udp" {
			assert.Equal(t, udpSource, rule.Sport)
			assert.Equal(t, udpDest, rule.Dport)
		}
	}

	for _, rule := range result.Egress {
		if rule.L4proto != "udp" && rule.L4proto != "tcp" {
			assert.FailNow(t, "unrecognized protocol", rule.L4proto)
		}
		if rule.L4proto == "tcp" {
			assert.Equal(t, tcpSource, rule.Sport)
			assert.Equal(t, tcpDest, rule.Dport)
		}
		if rule.L4proto == "udp" {
			assert.Equal(t, udpSource, rule.Sport)
			assert.Equal(t, udpDest, rule.Dport)
		}
	}
}
