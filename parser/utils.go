package parser

import (
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
)

// BuildEgressConnectionTemplates builds rules for egress connections
func BuildEgressConnectionTemplates(dst, action string) pcn_types.ParsedRules {
	parsed := pcn_types.ParsedRules{}

	//	In the firewall, egress packets travel from the ingress chain to the egress chain
	//	That's why it is reversed here.
	if action == pcn_types.ActionForward {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackNew,
		})
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
		parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
			Src:       dst,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
	} else {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Dst:       dst,
			Action:    "drop",
			Conntrack: pcn_types.ConnTrackNew,
		})
	}

	return parsed
}

// BuildIngressConnectionTemplates builds rules for ingress connections
func BuildIngressConnectionTemplates(src, action string) pcn_types.ParsedRules {
	parsed := pcn_types.ParsedRules{}

	//	In the firewall, ingress packets travel from the egress chain to the ingress chain
	//	That's why it is reversed here.
	if action == pcn_types.ActionForward {
		parsed.Egress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackNew,
		})
		parsed.Egress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
		parsed.Ingress = append(parsed.Egress, k8sfirewall.ChainRule{
			Dst:       src,
			Action:    "forward",
			Conntrack: pcn_types.ConnTrackEstablished,
		})
	} else {
		parsed.Egress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Src:       src,
			Action:    "drop",
			Conntrack: pcn_types.ConnTrackNew,
		})
	}

	return parsed
}
