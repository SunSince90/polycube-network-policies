package parser

import (
	"fmt"

	controller "github.com/SunSince90/polycube-network-policies/controller"

	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycubenetwork.com/v1beta"

	//"fmt"

	"sync"

	//pcn_controllers "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/controllers"
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	k8sfirewall "github.com/SunSince90/polycube/src/components/k8s/utils/k8sfirewall"

	log "github.com/Sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
)

// PolycubeNetworkPolicyParser is the polycube network policy parser
type PolycubeNetworkPolicyParser interface {
	ParseRules(v1beta.PolycubeNetworkPolicyTarget, v1beta.PolycubeNetworkPolicyIngressRuleContainer, v1beta.PolycubeNetworkPolicyEgressRuleContainer, string) ([]pcn_types.ParsedRules, []pcn_types.ParsedRules)
	ParseIngress(v1beta.PolycubeNetworkPolicyTarget, v1beta.PolycubeNetworkPolicyIngressRuleContainer, string) []pcn_types.ParsedRules
	ParseEgress(v1beta.PolycubeNetworkPolicyEgressRuleContainer, string) []pcn_types.ParsedRules
	/*ParseIPBlock(*networking_v1.IPBlock, string) pcn_types.ParsedRules
	ParsePorts([]networking_v1.NetworkPolicyPort) []pcn_types.ProtoPort
	ParseSelectors(*meta_v1.LabelSelector, *meta_v1.LabelSelector, string, string) (pcn_types.ParsedRules, error)
	BuildActions([]networking_v1.NetworkPolicyIngressRule, []networking_v1.NetworkPolicyEgressRule, string) []pcn_types.FirewallAction
	GetConnectionTemplate(string, string, string, string, []pcn_types.ProtoPort) pcn_types.ParsedRules
	DoesPolicyAffectPod(*networking_v1.NetworkPolicy, *core_v1.Pod) bool*/
}

// PnpParser is the implementation of the default parser
type PnpParser struct {
	podController      controller.PodController
	serviceController  controller.ServiceController
	supportedProtocols string
	log                *log.Logger
}

// NewPolycubePolicyParser starts a new parser
func NewPolycubePolicyParser(podController controller.PodController, serviceController controller.ServiceController) PolycubeNetworkPolicyParser {
	return &PnpParser{
		podController:     podController,
		serviceController: serviceController,
		log:               log.New(),
	}
}

// ParseRules is a convenient method for parsing Ingress and Egress concurrently
func (p *PnpParser) ParseRules(target v1beta.PolycubeNetworkPolicyTarget, ingress v1beta.PolycubeNetworkPolicyIngressRuleContainer, egress v1beta.PolycubeNetworkPolicyEgressRuleContainer, currentNamespace string) ([]pcn_types.ParsedRules, []pcn_types.ParsedRules) {
	//-------------------------------------
	//	Init
	//-------------------------------------

	resultIngress := []pcn_types.ParsedRules{}
	resultEgress := []pcn_types.ParsedRules{}

	var parseWait sync.WaitGroup

	parseWait.Add(2)

	//-------------------------------------
	//	Parse the ingress rules
	//-------------------------------------

	go func() {
		defer parseWait.Done()
		resultIngress = p.ParseIngress(target, ingress, currentNamespace)
	}()

	//-------------------------------------
	//	Parse the egress rules
	//-------------------------------------

	go func() {
		defer parseWait.Done()
		resultEgress = p.ParseEgress(egress, currentNamespace)
	}()

	//	Wait for them to finish before doing the rest
	parseWait.Wait()

	//return parsed
	return resultIngress, resultEgress
}

// ParseIngress parses the Ingress section of a policy
func (p *PnpParser) ParseIngress(target v1beta.PolycubeNetworkPolicyTarget, ingress v1beta.PolycubeNetworkPolicyIngressRuleContainer, namespace string) []pcn_types.ParsedRules {

	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(p.log)
	l.WithFields(log.Fields{"by": "pnp-parser", "method": "ParseIngress"})
	parsed := []pcn_types.ParsedRules{}
	serviceProtocols := []v1beta.PolycubeNetworkPolicyProtocolContainer{}
	direction := "ingress"

	//-------------------------------------
	//	Target is a service?
	//-------------------------------------

	//	ParseIngress does not support ANY.
	//	So it must be called for every service.
	if target.Target == v1beta.ServiceTarget {
		_service, err := p.serviceController.GetServices(pcn_types.ObjectQuery{By: "name", Name: target.WithName}, pcn_types.ObjectQuery{By: "name", Name: namespace})
		if err != nil {
			l.Errorln("Error occurred while getting service", target.WithName, ". Going to stop now.")
			return parsed
		}

		if len(_service) < 1 {
			l.Warningln("Service with name", target.WithName, " not found. No need to generate any rules.")
		}

		service := _service[0]

		//	Has no selectors?
		if len(service.Spec.Selector) < 1 {
			l.Errorf("Target service %s has no selectors and this is not allowed.")
			return parsed
		}

		serviceProtocols, err = formatProtocolsFromService(service)
		if err != nil {
			log.Errorln("Could not get the service:", err, ". Going to stop parsing the policy.")
			return parsed
		}
	}

	//-------------------------------------
	//	Preliminary checks
	//-------------------------------------

	//	Allow all?
	if ingress.AllowAll != nil && *ingress.AllowAll == true {
		return []pcn_types.ParsedRules{
			buildIngressConnectionTemplates("", "forward", serviceProtocols),
		}
	}

	//	Drop all?
	if ingress.DropAll != nil && *ingress.DropAll == true {
		return []pcn_types.ParsedRules{
			buildIngressConnectionTemplates("", "drop", serviceProtocols),
		}
	}

	//	No rules?
	if len(ingress.Rules) < 1 {
		l.Errorln("There are no rules in ingress!")
		return parsed
	}

	//-------------------------------------
	//	Actual parsing
	//-------------------------------------
	for i, rule := range ingress.Rules {

		protocols := []v1beta.PolycubeNetworkPolicyProtocolContainer{}

		//	You have set service as target but also specified the ports: I take it as you want to override something.
		if len(rule.Protocols) < 1 && len(serviceProtocols) > 0 {
			protocols = serviceProtocols
		} else {
			protocols = rule.Protocols
		}

		//	Parse the peer
		generatedRules, err := p.ParsePeer(rule.From, protocols, namespace, direction, rule.Action)
		if err != nil {
			l.Errorf("Error while parsing rule #%d in ingress", i)
		} else {
			parsed = append(parsed, generatedRules)
		}

		// Parse the protocols for ingress
		/*for _, generated := range generatedRules.Ingress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.Dport = protocol.Ports.Source
				tempRule.Sport = protocol.Ports.Destination
				tempRule.L4proto = string(protocol.Protocol)
				parsedRule.Ingress = append(parsedRule.Ingress, tempRule)
			}
		}

		// parse the protocol for egress
		for _, generated := range generatedRules.Egress {
			for _, protocol := range rule.Protocols {
				tempRule := generated
				tempRule.Sport = protocol.Ports.Source
				tempRule.Dport = protocol.Ports.Destination
				tempRule.L4proto = string(protocol.Protocol)
				parsedRule.Egress = append(parsedRule.Egress, tempRule)
			}
		}*/

	}

	return parsed
}

// ParseEgress parses the Egress section of a policy
func (p *PnpParser) ParseEgress(egress v1beta.PolycubeNetworkPolicyEgressRuleContainer, namespace string) []pcn_types.ParsedRules {
	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(p.log)
	l.WithFields(log.Fields{"by": "pnp-parser", "method": "ParseEgress"})
	parsed := []pcn_types.ParsedRules{}
	direction := "egress"

	//-------------------------------------
	//	Preliminary checks
	//-------------------------------------

	//	Allow all?
	if egress.AllowAll != nil && *egress.AllowAll == true {
		return []pcn_types.ParsedRules{
			buildEgressConnectionTemplates("", "forward", []v1beta.PolycubeNetworkPolicyProtocolContainer{}),
		}
	}

	//	Drop all?
	if egress.DropAll != nil && *egress.DropAll == true {
		return []pcn_types.ParsedRules{
			buildEgressConnectionTemplates("", "drop", []v1beta.PolycubeNetworkPolicyProtocolContainer{}),
		}
	}

	//	No rules?
	if len(egress.Rules) < 1 {
		l.Errorln("There are no rules in egress!")
		return parsed
	}

	//-------------------------------------
	//	Actual parsing
	//-------------------------------------
	for i, rule := range egress.Rules {

		//	Parse the peer
		generatedRules, err := p.ParsePeer(rule.To, rule.Protocols, namespace, direction, rule.Action)
		if err != nil {
			l.Errorf("Error while parsing rule #%d in egress", i)
		} else {
			parsed = append(parsed, generatedRules)
		}
	}

	return parsed
}

// ParsePeer is a convenient method to parse the peer. Works for both ingress and egress connections
func (p *PnpParser) ParsePeer(peer v1beta.PolycubeNetworkPolicyPeer, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer, namespace, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) (pcn_types.ParsedRules, error) {

	//	Pod?
	if peer.Peer == v1beta.PodPeer {
		return p.ParsePod(peer, protocols, namespace, direction, action)
	}

	//	Service, but only for egress
	//	It doesn't make any sense protecting yourself FROM a service: they just expose something for you to use, man.
	if peer.Peer == v1beta.ServicePeer && direction == "egress" {
		return p.ParseService(peer, namespace, direction, action)
	}

	//	The World?
	if peer.Peer == v1beta.WorldPeer {
		return p.ParseWorld(peer.WithIP, protocols, direction, action), nil
	}

	return pcn_types.ParsedRules{}, nil
}

// ParseWorld parses world type peer
func (p *PnpParser) ParseWorld(ips v1beta.PolycubeNetworkPolicyWithIP, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) pcn_types.ParsedRules {
	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}

	//	The list
	for _, cidr := range ips.List {
		rules := pcn_types.ParsedRules{}

		if direction == "ingress" {
			rules = buildIngressConnectionTemplates(cidr, string(action), protocols)
		} else {
			rules = buildEgressConnectionTemplates(cidr, string(action), protocols)
		}

		parsed.Ingress = append(parsed.Ingress, rules.Ingress...)
		parsed.Egress = append(parsed.Egress, rules.Egress...)
	}

	return parsed
}

// ParsePod parses pod type peer
func (p *PnpParser) ParsePod(peer v1beta.PolycubeNetworkPolicyPeer, protocols []v1beta.PolycubeNetworkPolicyProtocolContainer, namespace, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) (pcn_types.ParsedRules, error) {
	//-------------------------------------
	//	Init
	//-------------------------------------

	parsed := pcn_types.ParsedRules{
		Ingress: []k8sfirewall.ChainRule{},
		Egress:  []k8sfirewall.ChainRule{},
	}
	podsFound := []core_v1.Pod{}
	anyPod := (peer.Any != nil && *peer.Any == true)

	//	Default the OnNamespace to use the one of the policy
	if peer.OnNamespace == nil {
		peer.OnNamespace = &v1beta.PolycubeNetworkPolicyNamespaceSelector{
			WithNames: []string{namespace},
		}
	}

	anyNs := (peer.OnNamespace.Any != nil && *peer.OnNamespace.Any == true)
	queryP := buildPodQuery(peer.WithLabels, anyPod)

	//-------------------------------------
	//	Get the pods
	//-------------------------------------

	if len(peer.OnNamespace.WithNames) > 0 {
		for _, ns := range peer.OnNamespace.WithNames {
			queryN := buildNamespaceQuery(ns, nil, false)

			//	Now get the pods
			found, err := p.podController.GetPods(queryP, queryN)
			if err != nil {
				return parsed, fmt.Errorf("Error while trying to get pods with labels %+v on namespace %s, error: %s", peer.WithLabels, ns, err.Error())
			}
			podsFound = append(podsFound, found...)
		}
	} else {
		// This also covers the case of anyNs = true
		queryN := buildNamespaceQuery("", peer.OnNamespace.WithLabels, anyNs)

		//	Now get the pods
		found, err := p.podController.GetPods(queryP, queryN)
		if err != nil {
			return parsed, fmt.Errorf("Error while trying to get pods with labels %+v on namespace with labels %v, error: %s", peer.WithLabels, peer.OnNamespace.WithLabels, err.Error())
		}
		podsFound = append(podsFound, found...)
	}

	//-------------------------------------
	//	Generate the rules for each found pod
	//-------------------------------------

	for _, pod := range podsFound {
		rules := pcn_types.ParsedRules{}

		if direction == "ingress" {
			rules = buildIngressConnectionTemplates(pod.Status.PodIP, string(action), protocols)
		} else {
			rules = buildEgressConnectionTemplates(pod.Status.PodIP, string(action), protocols)
		}

		parsed.Ingress = append(parsed.Ingress, rules.Ingress...)
		parsed.Egress = append(parsed.Egress, rules.Egress...)
	}

	return parsed, nil
}

// ParseService parses service type peer
func (p *PnpParser) ParseService(peer v1beta.PolycubeNetworkPolicyPeer, namespace, direction string, action v1beta.PolycubeNetworkPolicyRuleAction) (pcn_types.ParsedRules, error) {
	//-------------------------------------
	//	Init
	//-------------------------------------
	l := log.NewEntry(p.log)
	l.WithFields(log.Fields{"by": "pnp-parser", "method": "ParseService"})
	parsed := pcn_types.ParsedRules{}
	servicesFound := []core_v1.Service{}
	anyS := (peer.Any != nil && *peer.Any == true)

	//	Default the OnNamespace to use the one of the policy
	if peer.OnNamespace == nil {
		peer.OnNamespace = &v1beta.PolycubeNetworkPolicyNamespaceSelector{
			WithNames: []string{namespace},
		}
	}

	anyNs := (peer.OnNamespace.Any != nil && *peer.OnNamespace.Any == true)
	queryS := buildServiceQuery(peer.WithName, anyS)

	//-------------------------------------
	//	Get the services
	//-------------------------------------

	//	Check the namespace
	if len(peer.OnNamespace.WithNames) > 0 {
		for _, ns := range peer.OnNamespace.WithNames {
			queryN := buildNamespaceQuery(ns, nil, false)

			//	Now get the service
			found, err := p.serviceController.GetServices(queryS, queryN)
			if err != nil {
				return parsed, fmt.Errorf("Error while trying to get pods with labels %+v on namespace %s, error: %s", peer.WithLabels, ns, err.Error())
			}
			servicesFound = append(servicesFound, found...)
		}
	} else {
		// This also covers the case of nsAny = true
		queryN := buildNamespaceQuery("", peer.OnNamespace.WithLabels, anyNs)

		//	Now get the services
		found, err := p.serviceController.GetServices(queryS, queryN)
		if err != nil {
			return parsed, fmt.Errorf("Error while trying to get pods with labels %+v on namespace with labels %v, error: %s", peer.WithLabels, peer.OnNamespace.WithLabels, err.Error())
		}
		servicesFound = append(servicesFound, found...)
	}

	//-------------------------------------
	//	Loop through all services
	//-------------------------------------

	for _, serv := range servicesFound {
		// Is this a service without selectors? those are not supported yet.
		// In order to provide this service, the firewall should be changed to react to endpoints changes as well.
		// While not hard at all, it would further complicate the model (it requires at least an endpoint watcher/informer).
		// So, for now, it is not supported.
		if len(serv.Spec.Selector) < 1 {
			l.Warningf("Warning: service %s is a service with no selector, and it is not supported yet. No rules are going to be generated for it.", serv.Name)
		} else {
			protocols, err := formatProtocolsFromService(serv)
			if err != nil {
				log.Errorln("Could not get the service:", err, ". No rules are going to generated for it.")
			} else {
				//	Now get the pods for it.
				//	In order to do this, we're going to leverage on ParsePods by creating a fake peer using the service selector as labels
				//	and the service namespace as the namespace
				fakePeer := v1beta.PolycubeNetworkPolicyPeer{
					Peer:       v1beta.PodPeer,
					WithLabels: serv.Spec.Selector,
					OnNamespace: &v1beta.PolycubeNetworkPolicyNamespaceSelector{
						WithNames: []string{serv.Namespace},
					},
				}

				generatedRules, err := p.ParsePod(fakePeer, protocols, serv.Namespace, direction, action)
				if err != nil {
					l.Errorln("Error while generating rules for service peer", serv.Name)
				} else {
					//	Finally, add the pods... phew...
					parsed.Ingress = append(parsed.Ingress, generatedRules.Ingress...)
					parsed.Egress = append(parsed.Egress, generatedRules.Egress...)
				}
			}
		}
	}

	return parsed, nil
}
