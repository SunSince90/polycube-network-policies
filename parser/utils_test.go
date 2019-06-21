package parser

import (
	"testing"

	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

func TestBuildNsQuery(t *testing.T) {
	//	Any is true and takes precedence
	namespace := "ns"
	nsLabels := map[string]string{"name": "ns"}
	result := BuildNamespaceQuery(namespace, nsLabels, true)

	assert.Equal(t, "name", result.By)
	assert.Equal(t, "*", result.Name)
	assert.Empty(t, result.Labels)

	//	Any is not true, name takes precedence

	result = BuildNamespaceQuery(namespace, nsLabels, false)

	assert.Equal(t, "name", result.By)
	assert.Equal(t, namespace, result.Name)
	assert.Empty(t, result.Labels)

	result = BuildNamespaceQuery("", nsLabels, false)

	assert.Equal(t, "labels", result.By)
	assert.Equal(t, nsLabels, result.Labels)
	assert.Empty(t, result.Name)
}

func TestBuildPodQuery(t *testing.T) {
	//	Any is true and takes precedence
	labels := map[string]string{"name": "tt"}
	result := BuildPodQuery(labels, true)

	assert.Equal(t, "name", result.By)
	assert.Equal(t, "*", result.Name)
	assert.Empty(t, result.Labels)

	//	Any is not true

	result = BuildPodQuery(labels, false)

	assert.Equal(t, "labels", result.By)
	assert.Equal(t, labels, result.Labels)
	assert.Empty(t, result.Name)
}

func TestServicePodQuery(t *testing.T) {
	name := "serv"
	result := BuildServiceQuery(name, true)

	assert.Equal(t, "name", result.By)
	assert.Equal(t, "*", result.Name)
	assert.Empty(t, result.Labels)

	result = BuildServiceQuery(name, false)
	assert.Equal(t, "name", result.By)
	assert.Equal(t, name, result.Name)
	assert.Empty(t, result.Labels)
}

func TestGetProtocolsFromService(t *testing.T) {
	serv := core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "service",
		},
		Spec: core_v1.ServiceSpec{
			Selector: map[string]string{
				"name": "service",
			},
			Ports: []core_v1.ServicePort{
				core_v1.ServicePort{
					Protocol: core_v1.ProtocolSCTP,
				},
			},
		},
	}

	result, err := formatProtocolsFromService(serv)
	assert.NotEmpty(t, err)
	assert.Empty(t, result)

	serv.Spec.Ports = []core_v1.ServicePort{
		core_v1.ServicePort{
			Protocol: core_v1.ProtocolTCP,
			Port:     8080,
		},
		core_v1.ServicePort{
			Protocol: core_v1.ProtocolUDP,
			Port:     9090,
		},
	}

	result, err = formatProtocolsFromService(serv)
	assert.Empty(t, err)
	assert.NotEmpty(t, result)

	assert.Equal(t, v1beta.TCP, result[0].Protocol)
	assert.Equal(t, int32(8080), result[0].Ports.Destination)
	assert.Equal(t, v1beta.UDP, result[1].Protocol)
	assert.Equal(t, int32(9090), result[1].Ports.Destination)

}
