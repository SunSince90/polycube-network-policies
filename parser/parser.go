package parser

import (
	"fmt"

	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycubenetwork.com/v1beta"

	//"fmt"
	"sort"
	"strings"
	"sync"

	pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/sirupsen/logrus"
	//core_v1 "k8s.io/api/core/v1"
	networking_v1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolycubeNetworkPolicyParser is the polycube network policy parser
type PolycubeNetworkPolicyParser interface {
	ParseRules(v1beta.PolycubeNetworkPolicyIngressRuleContainer, v1beta.PolycubeNetworkPolicyEgressRuleContainer, string) pcn_types.ParsedRules
	ParseIngress([]v1beta.PolycubeNetworkPolicyIngressRule, string) pcn_types.ParsedRules
	/*ParseEgress([]v1beta.PolycubeNetworkPolicyEgressRule, string) pcn_types.ParsedRules
	ParseIPBlock(*networking_v1.IPBlock, string) pcn_types.ParsedRules
	ParsePorts([]networking_v1.NetworkPolicyPort) []pcn_types.ProtoPort
	ParseSelectors(*meta_v1.LabelSelector, *meta_v1.LabelSelector, string, string) (pcn_types.ParsedRules, error)
	BuildActions([]networking_v1.NetworkPolicyIngressRule, []networking_v1.NetworkPolicyEgressRule, string) []pcn_types.FirewallAction
	GetConnectionTemplate(string, string, string, string, []pcn_types.ProtoPort) pcn_types.ParsedRules
	DoesPolicyAffectPod(*networking_v1.NetworkPolicy, *core_v1.Pod) bool*/
}

// PnpParser is the implementation of the default parser
type PnpParser struct {
	podController      pcn_controllers.PodController
	supportedProtocols string
	log                *log.Logger
}

// newPolycubePolicyParser starts a new parser
func newPolycubePolicyParser(podController pcn_controllers.PodController) PolycubeNetworkPolicyParser {
	return &PnpParser{
		podController: podController,
		log:           log.New(),
	}
}

// ParseRules is a convenient method for parsing Ingress and Egress concurrently
func (p *PnpParser) ParseRules(ingress v1beta.PolycubeNetworkPolicyIngressRuleContainer, egress v1beta.PolycubeNetworkPolicyEgressRuleContainer, currentNamespace string) pcn_types.ParsedRules {
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	var parseWait sync.WaitGroup
	var lock sync.Mutex

	parseWait.Add(2)

	//-------------------------------------
	//	Parse the ingress rules
	//-------------------------------------

	go func() {
		defer parseWait.Done()
		result := p.ParseIngress(ingress, currentNamespace)

		lock.Lock()
		parsed.Ingress = append(parsed.Ingress, result.Ingress...)
		parsed.Egress = append(parsed.Egress, result.Egress...)
		lock.Unlock()
	}()

	//-------------------------------------
	//	Parse the egress rules
	//-------------------------------------

	go func() {
		defer parseWait.Done()
		result := p.ParseEgress(egress, currentNamespace)

		lock.Lock()
		parsed.Ingress = append(parsed.Ingress, result.Ingress...)
		parsed.Egress = append(parsed.Egress, result.Egress...)
		lock.Unlock()
	}()

	//	Wait for them to finish before doing the rest
	parseWait.Wait()

	return parsed
}

// ParseIngress parses the Ingress section of a policy
func (p *PnpParser) ParseIngress(ingress v1beta.PolycubeNetworkPolicyIngressRuleContainer, namespace string) pcn_types.ParsedRules {

	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(p.log)
	l.WithFields(log.Fields{"by": "pnp-parser", "method": "ParseIngress"})
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}
	direction := "ingress"

	//-------------------------------------
	//	Preliminary checks
	//-------------------------------------

	//	Allow all?
	if ingress.AllowAll != nil && *ingress.AllowAll == true {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Action: pcn_types.ActionForward,
		})

		return parsed
	}

	//	Drop all?
	if ingress.DropAll != nil && *ingress.DropAll == true {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Action: pcn_types.ActionDrop,
		})

		return parsed
	}

	//	No rules?
	if len(ingress.Rules) < 1 && len(ingress.ServiceRules) < 1 {
		return parsed
	}

	//-------------------------------------
	//	Actual parsing
	//-------------------------------------
	for _, rule := range ingress.Rules {

		//	Parse the peer
		generatedRules := p.ParsePeer(rule.From, namespace, "ingress", rule.Action)

		// Parse the protocols for ingress
		for _, generated := range generatedRules.Ingress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.L4proto = protocol
				tempRule.Dport = protocol.Destination
				tempRule.Sport = protocol.Source
				parsed.Ingress = append(parsed.Ingress, tempRule)
			}
		}

		// parse the protocol for egress
		for _, generated := range generatedRules.Egress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.L4proto = protocol
				tempRule.Dport = protocol.Destination
				tempRule.Sport = protocol.Source
				parsed.Egress = append(parsed.Egress, tempRule)
			}
		}
	}

	return parsed
}

// ParseIngress parses the Ingress section of a policy
func (p *PnpParser) ParseIngress(ingress v1beta.PolycubeNetworkPolicyIngressRuleContainer, namespace string) pcn_types.ParsedRules {

	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(p.log)
	l.WithFields(log.Fields{"by": "pnp-parser", "method": "ParseIngress"})
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}
	direction := "ingress"

	//-------------------------------------
	//	Preliminary checks
	//-------------------------------------

	//	Allow all?
	if ingress.AllowAll != nil && *ingress.AllowAll == true {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Action: pcn_types.ActionForward,
		})

		return parsed
	}

	//	Drop all?
	if ingress.DropAll != nil && *ingress.DropAll == true {
		parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
			Action: pcn_types.ActionDrop,
		})

		return parsed
	}

	//	No rules?
	if len(ingress.Rules) < 1 && len(ingress.ServiceRules) < 1 {
		return parsed
	}

	//-------------------------------------
	//	Actual parsing
	//-------------------------------------
	for _, rule := range ingress.Rules {

		//	Parse the peer
		generatedRules := p.ParsePeer(rule.From, namespace, "ingress", rule.Action)

		// Parse the protocols for ingress
		for _, generated := range generatedRules.Ingress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.L4proto = protocol
				tempRule.Dport = protocol.Destination
				tempRule.Sport = protocol.Source
				parsed.Ingress = append(parsed.Ingress, tempRule)
			}
		}

		// parse the protocol for egress
		for _, generated := range generatedRules.Egress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.L4proto = protocol
				tempRule.Dport = protocol.Destination
				tempRule.Sport = protocol.Source
				parsed.Egress = append(parsed.Egress, tempRule)
			}
		}
	}

	return parsed
}

func (p *PnpParser) ParsePeer(peer v1beta.PolycubeNetworkPolicyPeer, namespace, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) pcn_types.ParsedRules {

	//	Pod?
	if peer.Peer == v1beta.PodPeer {
		result, err := p.ParsePod(peer, namespace, direction, action)
		if err != nil {
			log.Errorln("Could not parse pod correctly")
		}
	}

	//	Deployment
	if peer.Peer == v1beta.DeploymentPeer {
		find := v1beta.PolycubeNetworkPolicyPeer{
			Peer: v1beta.PodPeer,
			WithLabels: map[string]string{
				"polycubenetwork.com/deployment": peer.WithName,
			},
			OnNamespace: peer.OnNamespace,
		}
		result, err := p.ParsePod(find, namespace, direction, action)
		if err != nil {
			log.Errorln("Could not parse pod correctly")
		}
	}

	//	The World?
	if peer.Peer == v1beta.WorldPeer {
		return p.ParseWolrd(peer.WithIP, direction, action)
	}

	return pcn_types.ParsedRules{}
}

func (p *PnpParser) ParseWolrd(ips v1beta.PolycubeNetworkPolicyWithIP, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) pcn_types.ParsedRules {
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	The list
	for _, cidr := range ips.List {
		result := pcn_types.ParsedRules{}
		if direction == "ingress" {
			if action == v1beta.AllowAction {
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackNew,
				})
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
			} else {
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       cidr,
					Action:    "drop",
					Conntrack: pcn_types.ConnTrackNew,
				})
			}
		} else {
			if action == v1beta.AllowAction {
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackNew,
				})
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       cidr,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
			} else {
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       cidr,
					Action:    "drop",
					Conntrack: pcn_types.ConnTrackNew,
				})
			}
		}
	}

	return parsed
}

func (p *PnpParser) ParsePod(peer v1beta.PolycubeNetworkPolicyPeer, namespace, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) (pcn_types.ParsedRules, error) {
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	nsLabels := map[string]string{}

	// has namespace?
	if peer.OnNamespace != nil {
		if len(peer.OnNamespace.WithName) > 0 {
			namespace = peer.OnNamespace.WithName
		} else {
			nsLabels = peer.OnNamespace.WithLabels
		}
	}

	queryP, queryN := p.buildPodQueries(peer.WithLabels, nsLabels, peer.Any, peer.OnNamespace.Any, namespace)

	//	Now get the pods
	podsFound, err := p.podController.GetPods(queryP, queryN)
	if err != nil {
		return parsed, fmt.Errorf("Error while trying to get pods %s", err.Error())
	}

	//	Now build the pods
	for _, pod := range podsFound {
		if direction == "ingress" {
			if action == v1beta.AllowAction {
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackNew,
				})
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
			} else {
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       pod.Status.PodIP,
					Action:    "drop",
					Conntrack: pcn_types.ConnTrackNew,
				})
			}
		} else {
			if action == v1beta.AllowAction {
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackNew,
				})
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
				parsed.Ingress = append(parsed.Ingress, k8sfirewall.ChainRule{
					Src:       pod.Status.PodIP,
					Action:    "forward",
					Conntrack: pcn_types.ConnTrackEstablished,
				})
			} else {
				parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
					Dst:       pod.Status.PodIP,
					Action:    "drop",
					Conntrack: pcn_types.ConnTrackNew,
				})
			}
		}
	}

	return parsed
}

// ParseEgress parses the Egress section of a policy
/*func (p *PnpParser) ParseEgress(rules []networking_v1.NetworkPolicyEgressRule, namespace string) pcn_types.ParsedRules {

	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(d.log)
	l.WithFields(log.Fields{"by": DPS, "method": "ParseEgress"})
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}
	direction := "egress"

	//-------------------------------------
	//	Preliminary checks
	//-------------------------------------

	//	Rules is nil?
	if rules == nil {
		return parsed
	}

	//	No rules?
	if len(rules) < 1 {
		//	Rules is empty: nothing is accepted
		parsed.Egress = append(parsed.Egress, k8sfirewall.ChainRule{
			Action: pcn_types.ActionDrop,
		})
		return parsed
	}

	//-------------------------------------
	//	Actual parsing
	//-------------------------------------

	for _, rule := range rules {

		//	The ports and rules generated in this iteration.
		generatedPorts := []pcn_types.ProtoPort{}
		generatedIngressRules := []k8sfirewall.ChainRule{}
		generatedEgressRules := []k8sfirewall.ChainRule{}

		//	Tells if we can go on parsing rules
		proceed := true

		//-------------------------------------
		//	Protocol & Port
		//-------------------------------------

		//	First, parse the protocol: so that if an unsupported protocol is listed, we silently ignore it.
		//	By doing it this way we don't have to remove rules later on
		if len(rule.Ports) > 0 {
			generatedPorts = d.ParsePorts(rule.Ports)

			//	If this rule consists of only unsupported protocols, then we can't go on!
			//	If we did, we would be creating wrong rules!
			//	We just need to ignore the rules, for now.
			//	But if there is at least one supported protocol, then we can proceed
			if len(generatedPorts) == 0 {
				proceed = false
			}
		}

		//-------------------------------------
		//	Peers
		//-------------------------------------

		//	To is {} ?
		if rule.To == nil && proceed {
			result := d.GetConnectionTemplate(direction, "", "", pcn_types.ActionForward, []pcn_types.ProtoPort{})
			generatedIngressRules = append(generatedIngressRules, result.Ingress...)
			generatedEgressRules = append(generatedEgressRules, result.Egress...)
		}

		for i := 0; rule.To != nil && i < len(rule.To) && proceed; i++ {
			to := rule.To[i]

			//	IPBlock?
			if to.IPBlock != nil {
				ipblock := d.ParseIPBlock(to.IPBlock, direction)
				generatedIngressRules = append(generatedIngressRules, ipblock.Ingress...)
				generatedEgressRules = append(generatedEgressRules, ipblock.Egress...)
			}

			//	PodSelector Or NamespaceSelector?
			if to.PodSelector != nil || to.NamespaceSelector != nil {
				rulesGot, err := d.ParseSelectors(to.PodSelector, to.NamespaceSelector, namespace, direction)

				if err == nil {
					if len(rulesGot.Ingress) > 0 {
						generatedIngressRules = append(generatedIngressRules, rulesGot.Ingress...)
					}
					if len(rulesGot.Egress) > 0 {
						generatedEgressRules = append(generatedEgressRules, rulesGot.Egress...)
					}
				} else {
					l.Errorln("Error while parsing selectors:", err)
				}
			}
		}

		//-------------------------------------
		//	Finalize
		//-------------------------------------
		rulesWithPorts := d.insertPorts(generatedIngressRules, generatedEgressRules, generatedPorts)
		parsed.Ingress = append(parsed.Ingress, rulesWithPorts.Ingress...)
		parsed.Egress = append(parsed.Egress, rulesWithPorts.Egress...)
	}

	return parsed
}*/

// insertPorts will complete the rules by adding the appropriate ports
/*func (p *PnpParser) insertPorts(generatedIngressRules, generatedEgressRules []k8sfirewall.ChainRule, generatedPorts []pcn_types.ProtoPort) pcn_types.ParsedRules {

	//	Don't make me go through this if there are no ports
	if len(generatedPorts) < 1 {
		return pcn_types.ParsedRules{
			Ingress: generatedIngressRules,
			Egress:  generatedEgressRules,
		}
	}

	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	var waitForChains sync.WaitGroup
	waitForChains.Add(2)

	go func() {
		defer waitForChains.Done()
		//	Finally, for each parsed rule, apply the ports that have been found
		//	But only if you have at least one port
		for i := 0; i < len(generatedIngressRules); i++ {
			rule := generatedIngressRules[i]
			for _, generatedPort := range generatedPorts {
				edited := rule
				edited.Dport = generatedPort.Port
				edited.L4proto = generatedPort.Protocol
				parsed.Ingress = append(parsed.Ingress, edited)
			}
		}
	}()

	go func() {
		defer waitForChains.Done()
		for i := 0; i < len(generatedEgressRules); i++ {
			rule := generatedEgressRules[i]
			for _, generatedPort := range generatedPorts {
				edited := rule
				edited.Sport = generatedPort.Port
				edited.L4proto = generatedPort.Protocol
				parsed.Egress = append(parsed.Egress, edited)
			}
		}
	}()
	waitForChains.Wait()

	return parsed
}*/

// ParseIPBlock will parse the IPBlock from the network policy and return the correct rules
/*func (p *PnpParser) ParseIPBlock(block *networking_v1.IPBlock, k8sDirection string) pcn_types.ParsedRules {

	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	Actually, these two cannot happen with kubernetes
	if block == nil {
		return parsed
	}

	if len(block.CIDR) < 1 {
		return parsed
	}

	//	Add the default one
	cidrRules := pcn_types.ParsedRules{}
	if k8sDirection == "ingress" {
		cidrRules = d.GetConnectionTemplate(k8sDirection, block.CIDR, "", pcn_types.ActionForward, []pcn_types.ProtoPort{})
	} else {
		cidrRules = d.GetConnectionTemplate(k8sDirection, "", block.CIDR, pcn_types.ActionForward, []pcn_types.ProtoPort{})
	}

	parsed.Ingress = append(parsed.Ingress, cidrRules.Ingress...)
	parsed.Egress = append(parsed.Egress, cidrRules.Egress...)

	//	Loop through all exceptions
	for _, exception := range block.Except {
		exceptionRule := k8sfirewall.ChainRule{
			Action:    pcn_types.ActionDrop,
			Conntrack: pcn_types.ConnTrackNew,
		}

		if k8sDirection == "ingress" {
			exceptionRule.Src = exception
			parsed.Ingress = append(parsed.Ingress, exceptionRule)
		} else {
			exceptionRule.Dst = exception
			parsed.Egress = append(parsed.Egress, exceptionRule)
		}
	}

	return parsed
}*/

// ParsePorts will parse the protocol and port and get the desired ports in a format that the firewall will understand
/*func (p *PnpParser) ParsePorts(ports []networking_v1.NetworkPolicyPort) []pcn_types.ProtoPort {

	//	Init
	generatedPorts := []pcn_types.ProtoPort{}

	for _, port := range ports {

		//	If protocol is nil, then we have to get all protocols
		if port.Protocol == nil {

			//	If the port is not nil, default port is not 0
			var defaultPort int32
			if port.Port != nil {
				defaultPort = int32(port.Port.IntValue())
			}

			generatedPorts = append(generatedPorts, pcn_types.ProtoPort{
				Port: defaultPort,
			})

		} else {
			//	else parse the protocol
			supported, proto, port := d.parseProtocolAndPort(port)

			//	Our firewall does not support SCTP, so we check if protocol is supported
			if supported {
				generatedPorts = append(generatedPorts, pcn_types.ProtoPort{
					Protocol: proto,
					Port:     port,
				})
			}
		}
	}

	return generatedPorts
}*/

// parseProtocolAndPort parses the protocol in order to know if it is supported by the firewall manager
/*func (p *PnpParser) parseProtocolAndPort(pp networking_v1.NetworkPolicyPort) (bool, string, int32) {

	//	Not sure if port can be nil, but it doesn't harm to do a simple reset
	var port int32
	if pp.Port != nil {
		port = int32(pp.Port.IntValue())
	}

	//	TCP?
	if *pp.Protocol == core_v1.ProtocolTCP {
		return true, "TCP", port
	}

	//	UDP?
	if *pp.Protocol == core_v1.ProtocolUDP {
		return true, "UDP", port
	}

	//	Not supported ¯\_(ツ)_/¯
	return false, "", 0
}*/

// ParseSelectors will parse the PodSelector or the NameSpaceSelector of a policy.
// It returns the appropriate rules for the specified pods
/*func (p *PnpParser) ParseSelectors(podSelector, namespaceSelector *meta_v1.LabelSelector, namespace, direction string) (pcn_types.ParsedRules, error) {

	//	init
	rules := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	First build the query
	podQuery, nsQuery, err := d.buildPodQueries(podSelector, namespaceSelector, namespace)
	if err != nil {
		return rules, err
	}

	//	Now get the pods
	podsFound, err := d.podController.GetPods(podQuery, nsQuery)
	if err != nil {
		return rules, fmt.Errorf("Error while trying to get pods %s", err.Error())
	}

	//	Now build the pods
	for _, pod := range podsFound {
		parsed := pcn_types.ParsedRules{}
		if direction == "ingress" {
			parsed = d.GetConnectionTemplate(direction, pod.Status.PodIP, "", pcn_types.ActionForward, []pcn_types.ProtoPort{})
		} else {
			parsed = d.GetConnectionTemplate(direction, "", pod.Status.PodIP, pcn_types.ActionForward, []pcn_types.ProtoPort{})
		}

		rules.Ingress = append(rules.Ingress, parsed.Ingress...)
		rules.Egress = append(rules.Egress, parsed.Egress...)
	}

	return rules, nil
}*/

// buildPodQueries builds the queries to be directed to the pod controller, in order to get the desired pods.
func (p *PnpParser) buildPodQueries(podSelector, namespaceSelector map[string]string, anyPod *bool, anyNs *bool, namespace string) (pcn_types.ObjectQuery, pcn_types.ObjectQuery) {

	//	Init
	queryPod := pcn_types.ObjectQuery{}
	queryNs := pcn_types.ObjectQuery{}

	if anyPod != nil && *anyPod == true {
		queryPod = pcn_types.ObjectQuery{
			By:   "name",
			Name: "*",
		}
	} else {
		queryPod = pcn_types.ObjectQuery{
			By:     "labels",
			Labels: podSelector,
		}
	}

	if anyNs != nil && *anyNs == true {
		queryNs = pcn_types.ObjectQuery{
			By:   "name",
			Name: "*",
		}
	} else {
		if len(namespace) > 0 {
			queryNs = pcn_types.ObjectQuery{
				By:   "name",
				Name: namespace,
			}
		} else {
			queryNs = pcn_types.ObjectQuery{
				By:     "labels",
				Labels: namespaceSelector,
			}
		}
	}

	return queryPod, queryNs, nil
}

// DoesPolicyAffectPod checks if the provided policy affects the provided pod, returning TRUE if it does
/*func (p *PnpParser) DoesPolicyAffectPod(policy *networking_v1.NetworkPolicy, pod *core_v1.Pod) bool {

	//	MatchExpressions? (we don't support them yet)
	if len(policy.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}

	//	Not in the same namespace?
	if policy.Namespace != pod.Namespace {
		return false
	}

	//	No labels in the policy? (= must be applied by all pods)
	if len(policy.Spec.PodSelector.MatchLabels) < 1 {
		return true
	}

	//	No labels in the pod?
	//	(if you're here, it means that there are labels in the policy. But this pod has no labels, so this policy does not apply to it)
	if len(pod.Labels) < 1 {
		return false
	}

	//	Finally check the labels
	labelsFound := 0
	labelsToFind := len(policy.Spec.PodSelector.MatchLabels)
	for pKey, pValue := range policy.Spec.PodSelector.MatchLabels {
		_, exists := pod.Labels[pKey]

		if !exists {
			//	This policy label does not even exists in the pod: no point in checking the others
			return false
		}

		if pod.Labels[pKey] != pValue {
			//	This policy label exists but does not have the value we wanted: no point in going on checking the others
			return false
		}

		labelsFound++
	}

	if labelsFound == labelsToFind {
		//	We found all labels: the pod must enforce this policy!
		return true
	}

	return false
}*/

// GetConnectionTemplate builds a rule template based on connections
func (p *PnpParser) GetConnectionTemplate(direction, src, dst, action string /*, ports []pcn_types.ProtoPort*/) pcn_types.ParsedRules {

	twoRules := make([]k8sfirewall.ChainRule, 2)
	oneRule := make([]k8sfirewall.ChainRule, 1)

	twoRules[0] = k8sfirewall.ChainRule{
		Src:       src,
		Dst:       dst,
		Action:    action,
		Conntrack: pcn_types.ConnTrackNew,
	}
	twoRules[1] = k8sfirewall.ChainRule{
		Src:       src,
		Dst:       dst,
		Action:    action,
		Conntrack: pcn_types.ConnTrackEstablished,
	}
	oneRule[0] = k8sfirewall.ChainRule{
		Src:       dst,
		Dst:       src,
		Action:    action,
		Conntrack: pcn_types.ConnTrackEstablished,
	}

	if direction == "ingress" {

		/*if len(ports) > 0 {
			withPorts := p.insertPorts(twoRules, oneRule, ports)
			twoRules, oneRule = withPorts.Ingress, withPorts.Egress
		}*/

		return pcn_types.ParsedRules{
			Ingress: twoRules,
			Egress:  oneRule,
		}
	}

	/*if len(ports) > 0 {
		withPorts := p.insertPorts(oneRule, twoRules, ports)
		oneRule, twoRules = withPorts.Ingress, withPorts.Egress
	}*/

	return pcn_types.ParsedRules{
		Ingress: oneRule,
		Egress:  twoRules,
	}

}

//	buildActionKey returns a key to be used in the firewall actions (to know how they should react to a pod event)
func (p *PnpParser) buildActionKey(podLabels, nsLabels map[string]string, nsName string) string {
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

// BuildActions builds actions that are going to be used by firewalls so they know how to react to pods.
func (p *PnpParser) BuildActions(ingress []networking_v1.NetworkPolicyIngressRule, egress []networking_v1.NetworkPolicyEgressRule, currentNamespace string) []pcn_types.FirewallAction {
	fwActions := []pcn_types.FirewallAction{}
	var waitActions sync.WaitGroup
	waitActions.Add(2)

	selectorsChecker := func(podSelector, namespaceSelector *meta_v1.LabelSelector) (bool, map[string]string, map[string]string) {
		//	Matchexpression is not supported
		if (podSelector != nil && len(podSelector.MatchExpressions) > 0) ||
			(namespaceSelector != nil && len(namespaceSelector.MatchExpressions) > 0) {
			return false, nil, nil
		}

		//	If no selectors, then don't do anything
		if podSelector == nil && namespaceSelector == nil {
			return false, nil, nil
		}

		p := map[string]string{}
		n := map[string]string{}
		if podSelector != nil {
			p = podSelector.MatchLabels
		}

		if namespaceSelector != nil {
			n = namespaceSelector.MatchLabels
		} else {
			n = nil
		}

		return true, p, n
	}

	//-------------------------------------
	//	Ingress
	//-------------------------------------
	ingressActions := []pcn_types.FirewallAction{}
	/*go func() {
		defer waitActions.Done()
		if ingress == nil {
			return
		}

		for _, i := range ingress {

			ports := d.ParsePorts(i.Ports)

			for _, f := range i.From {
				action := pcn_types.FirewallAction{}

				ok, pod, ns := selectorsChecker(f.PodSelector, f.NamespaceSelector)

				if ok {

					action.PodLabels = pod
					action.NamespaceLabels = ns
					if ns == nil {
						action.NamespaceLabels = map[string]string{}
						action.NamespaceName = currentNamespace
					}

					action.Templates = d.GetConnectionTemplate("ingress", "", "", pcn_types.ActionForward, ports)
					action.Key = d.buildActionKey(action.PodLabels, action.NamespaceLabels, action.NamespaceName)
					ingressActions = append(ingressActions, action)
				}
			}
		}
	}()*/

	//-------------------------------------
	//	Egress
	//-------------------------------------
	/*egressActions := []pcn_types.FirewallAction{}
	go func() {
		defer waitActions.Done()
		if egress == nil {
			return
		}

		for _, e := range egress {

			ports := d.ParsePorts(e.Ports)

			for _, t := range e.To {

				action := pcn_types.FirewallAction{}
				ok, pod, ns := selectorsChecker(t.PodSelector, t.NamespaceSelector)

				if ok {

					action.PodLabels = pod
					action.NamespaceLabels = ns
					if ns == nil {
						action.NamespaceLabels = map[string]string{}
						action.NamespaceName = currentNamespace
					}

					action.Templates = d.GetConnectionTemplate("egress", "", "", pcn_types.ActionForward, ports)
					action.Key = d.buildActionKey(action.PodLabels, action.NamespaceLabels, action.NamespaceName)
					egressActions = append(egressActions, action)
				}
			}
		}
	}()*/

	waitActions.Wait()

	//fwActions = append(fwActions, ingressActions...)
	//fwActions = append(fwActions, egressActions...)
	return fwActions
}

/*func (p *PnpParser) generateRulesForPod(podsFound []core_v1.Pod, pod *core_v1.Pod, generatedPorts []pcn_types.ProtoPort, direction string) pcn_types.ParsedRules {
	generatedIngress := []k8sfirewall.ChainRule{}
	generatedEgress := []k8sfirewall.ChainRule{}

	for j := 0; j < len(podsFound); j++ {
		podFound := podsFound[j]
		if podFound.UID == pod.UID {
			for _, generatedPort := range generatedPorts {
				if direction == "ingress" {
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Dport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackNew,
					})
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Dport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Sport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
				}
				if direction == "egress" {
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Sport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackNew,
					})
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Sport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						L4proto:   generatedPort.Protocol,
						Dport:     generatedPort.Port,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
				}
			}
			if len(generatedPorts) < 1 {
				if direction == "ingress" {
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackNew,
					})
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
				}
				if direction == "egress" {
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackNew,
					})
					generatedEgress = append(generatedEgress, k8sfirewall.ChainRule{
						Dst:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
					generatedIngress = append(generatedIngress, k8sfirewall.ChainRule{
						Src:       pod.Status.PodIP,
						Action:    pcn_types.ActionForward,
						Conntrack: pcn_types.ConnTrackEstablished,
					})
				}
			}
		}
	}

	return pcn_types.ParsedRules{
		Ingress: generatedIngress,
		Egress:  generatedEgress,
	}
}*/
