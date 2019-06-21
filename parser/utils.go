package parser

import (
	"fmt"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"

	core_v1 "k8s.io/api/core/v1"

	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycubenetwork.com/v1beta"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"
)

// buildEgressConnectionTemplates builds rules for egress connections
func buildEgressConnectionTemplates(dst, action string, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer) pcn_types.ParsedRules {
	tempParsed := pcn_types.ParsedRules{}
	finalParsed := pcn_types.ParsedRules{}

	//------------------------------------------
	//	Without protocols
	//------------------------------------------
	//	In the firewall, egress packets travel from the ingress chain to the egress chain
	//	That's why it is reversed here.
	if action == pcn_types.ActionForward {
		tempParsed.Ingress = append(tempParsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackNew,
		})
		tempParsed.Ingress = append(tempParsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
		tempParsed.Egress = append(tempParsed.Egress, k8sfirewall.ChainRule{
			Src:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
	} else {
		tempParsed.Ingress = append(tempParsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "drop",
			Conntrack: pcn_types.ConnTrackNew,
		})
	}

	if len(protocols) < 1 {
		return tempParsed
	}

	//------------------------------------------
	//	With protocols
	//------------------------------------------

	for _, rule := range tempParsed.Ingress {
		for _, port := range protocols {
			newRule := rule
			newRule.L4proto = string(port.Protocol)
			newRule.Dport = port.Ports.Destination
			newRule.Sport = port.Ports.Source
			finalParsed.Ingress = append(finalParsed.Ingress, newRule)
		}
	}

	for _, rule := range tempParsed.Egress {
		for _, port := range protocols {
			newRule := rule
			newRule.L4proto = string(port.Protocol)
			newRule.Dport = port.Ports.Destination
			newRule.Sport = port.Ports.Source
			finalParsed.Egress = append(finalParsed.Egress, newRule)
		}
	}

	return finalParsed

}

// buildIngressConnectionTemplates builds rules for ingress connections
func buildIngressConnectionTemplates(src, action string, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer) pcn_types.ParsedRules {
	tempParsed := pcn_types.ParsedRules{}
	finalParsed := pcn_types.ParsedRules{}

	//------------------------------------------
	//	Without protocols
	//------------------------------------------
	//	In the firewall, ingress packets travel from the egress chain to the ingress chain
	//	That's why it is reversed here.
	if action == pcn_types.ActionForward {
		tempParsed.Egress = append(tempParsed.Egress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackNew,
		})
		tempParsed.Egress = append(tempParsed.Egress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
		tempParsed.Ingress = append(tempParsed.Ingress, k8sfirewall.ChainRule{
			Dst:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
	} else {
		tempParsed.Egress = append(tempParsed.Egress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "drop",
			Conntrack: pcn_types.ConnTrackNew,
		})
	}

	if len(protocols) < 1 {
		return tempParsed
	}

	//------------------------------------------
	//	With protocols
	//------------------------------------------

	for _, rule := range tempParsed.Egress {
		for _, port := range protocols {
			newRule := rule
			newRule.L4proto = string(port.Protocol)
			newRule.Dport = port.Ports.Destination
			newRule.Sport = port.Ports.Source
			finalParsed.Egress = append(finalParsed.Egress, newRule)
		}
	}

	for _, rule := range tempParsed.Ingress {
		for _, port := range protocols {
			newRule := rule
			newRule.L4proto = string(port.Protocol)
			newRule.Sport = port.Ports.Destination
			newRule.Dport = port.Ports.Source
			finalParsed.Ingress = append(finalParsed.Ingress, newRule)
		}
	}

	return finalParsed
}

// buildTemplates is just a shorthand for the ingress and egress ones
func buildTemplates(ip, action, direction string, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer) pcn_types.ParsedRules {
	if direction == "ingress" {
		return buildIngressConnectionTemplates(ip, action, protocols)
	}

	return buildEgressConnectionTemplates(ip, action, protocols)
}

// buildActionKey returns a key to be used in the firewall actions (to know how they should react to a pod event)
func buildActionKey(podLabels, nsLabels map[string]string, nsName string) string {
	key := ""
	//	NOTE: why do we sort keys? Because in go, iteration of a map is not order and not always fixed.
	//	So, by ordering the alphabetically we have a guarantuee that this function always returns the same expected result.
	//	BTW, pods and namespaces usally have very few keys (e.g.: including those appended by k8s as well, they should be less than 10)

	//-------------------------------------
	//	Namespace
	//-------------------------------------

	//	Namespace name always has precedence over labels
	if len(nsName) > 0 {
		key += "nsName:" + nsName
	} else {

		if len(nsLabels) > 0 {
			key += "nsLabels:"

			implodedLabels := []string{}
			for k, v := range nsLabels {
				implodedLabels = append(implodedLabels, k+"="+v)
			}
			sort.Strings(implodedLabels)
			key += strings.Join(implodedLabels, ",")
		} else {
			key += "nsName:*"
		}
	}

	key += "|"

	//-------------------------------------
	//	Pod
	//-------------------------------------

	//	Pod labels
	key += "podLabels:"
	if len(podLabels) < 1 {
		key += "*"
		return key
	}

	implodedLabels := []string{}
	for k, v := range podLabels {
		implodedLabels = append(implodedLabels, k+"="+v)
	}
	sort.Strings(implodedLabels)
	key += strings.Join(implodedLabels, ",")

	return key
}

// implodeLabels set labels in a key1=value1,key2=value2 format
func implodeLabels(labels map[string]string) string {
	implodedLabels := ""

	for k, v := range labels {
		implodedLabels += k + "=" + v + ","
	}

	return strings.Trim(implodedLabels, ",")
}

// BuildNamespaceQuery builds a namespace query
func BuildNamespaceQuery(name string, labels map[string]string, any bool) pcn_types.ObjectQuery {
	if !any {

		//	Name provided?
		if len(name) > 0 {
			return pcn_types.ObjectQuery{
				By:   "name",
				Name: name,
			}
		}

		//	Labels
		return pcn_types.ObjectQuery{
			By:     "labels",
			Labels: labels,
		}
	}

	//	Any namespace
	return pcn_types.ObjectQuery{
		By:   "name",
		Name: "*",
	}

}

// BuildPodQuery builds a query for pods
func BuildPodQuery(labels map[string]string, any bool) pcn_types.ObjectQuery {

	if !any {
		return pcn_types.ObjectQuery{
			By:     "labels",
			Labels: labels,
		}
	}

	return pcn_types.ObjectQuery{
		By:   "name",
		Name: "*",
	}
}

// BuildServiceQuery builds a query to get services from the service controller
func BuildServiceQuery(name string, any bool) pcn_types.ObjectQuery {
	if !any {
		return pcn_types.ObjectQuery{
			By:   "name",
			Name: name,
		}
	}

	return pcn_types.ObjectQuery{
		By:   "name",
		Name: "*",
	}
}

func formatProtocolsFromService(service core_v1.Service) ([]v1beta.PolycubeNetworkPolicyProtocolContainer, error) {

	//	Only SCTP?
	if len(service.Spec.Ports) == 1 && service.Spec.Ports[0].Protocol == core_v1.ProtocolSCTP {
		return []v1beta.PolycubeNetworkPolicyProtocolContainer{}, fmt.Errorf("service %s only has SCTP, going to stop now", service.Name)
	}

	serviceProtocols := []v1beta.PolycubeNetworkPolicyProtocolContainer{}

	//	Map kubernetes protocols to polycube's
	protoMap := map[core_v1.Protocol]v1beta.PolycubeNetworkPolicyProtocol{
		core_v1.ProtocolTCP: v1beta.TCP,
		core_v1.ProtocolUDP: v1beta.UDP,
	}

	//	Get the protocols and ports
	for _, port := range service.Spec.Ports {
		if port.Protocol != core_v1.ProtocolSCTP {
			serviceProtocols = append(serviceProtocols, v1beta.PolycubeNetworkPolicyProtocolContainer{
				Ports: v1beta.PolycubeNetworkPolicyPorts{
					Destination: port.Port,
				},
				Protocol: protoMap[port.Protocol],
			})
		} else {
			log.Warningf("Service %s contains an unsupported protocol: %s", service.Name, string(port.Protocol))
		}
	}

	return serviceProtocols, nil
}
