package v1beta

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolycubeNetworkPolicy is a network policy handled by polycube
type PolycubeNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// ApplyTo defines who this policy is intended for
	ApplyTo PolycubeNetworkPolicyTarget `json:"applyTo,omitempty"`
	// Spec of this policy
	Spec PolycubeNetworkPolicySpec `json:"spec,omitempty"`
}

// PolycubeNetworkPolicyTarget is the target of this policy
type PolycubeNetworkPolicyTarget struct {
	// Target is the object that should enforce this policy
	Target PolycubeNetworkPolicyTargetObject `json:"target,omitempty"`
	// +optional
	// If name and labels are irrelevant
	Any *bool `json:"any,omitempty"`
	// +optional
	// WithName specifies the name of the object. Valid only for Deployment
	WithName string `json:"withName,omitempty"`
	// +optional
	// WithLabels specifies the labels of the target. Valid only for Pod
	WithLabels map[string]string `json:"withLabels,omitempty"`
}

// PolycubeNetworkPolicyTargetObject is the target object
type PolycubeNetworkPolicyTargetObject string

const (
	// DeploymentTarget represents a Deployment
	DeploymentTarget PolycubeNetworkPolicyTargetObject = "deployment"
	// PodTarget represents a Pod
	PodTarget PolycubeNetworkPolicyTargetObject = "pod"
)

// PolycubeNetworkPolicySpec contains the specifications of this Network Policy
type PolycubeNetworkPolicySpec struct {
	// +optional
	// Description is the description of the policy
	Description string `json:"description,omitempty"`
	// +optional
	// IngressRules contains the ingress rules
	IngressRules PolycubeNetworkPolicyIngressRuleContainer `json:"ingressRules,omitempty"`
	// +optional
	// EgressRules contains the egress rules
	EngressRules PolycubeNetworkPolicyEgressRuleContainer `json:"egressRules,omitempty"`
}

// PolycubeNetworkPolicyIngressRuleContainer is a container of ingress rules
type PolycubeNetworkPolicyIngressRuleContainer struct {
	// +optional
	// DropAll specifies to drop everything in ingress
	DropAll *bool `json:"dropAll,omitempty"`
	// +optional
	// AllowAll specifies to allow anyone in ingress
	AllowAll *bool `json:"allowAll,omitempty"`
	// +optional
	// Rules is a list of ingress rules
	Rules []PolycubeNetworkPolicyIngressRule `json:"rules,omitempty"`
	// +optional
	// ServiceRules specifies that the rules are bound to services
	ServiceRules []PolycubeNetworkPolicyIngressServiceRuleContainer `json:"serviceRules,omitempty"`
}

// PolycubeNetworkPolicyEgressRuleContainer is a container of egress rules
type PolycubeNetworkPolicyEgressRuleContainer struct {
	// +optional
	// DropAll specifies to drop everything in egress
	DropAll *bool `json:"dropAll,omitempty"`
	// +optional
	// AllowAll specifies to allow anyone in egress
	AllowAll *bool `json:"allowAll,omitempty"`
	// +optional
	// Rules is a list of egress rules
	Rules []PolycubeNetworkPolicyEgressRule `json:"rules,omitempty"`
	// +optional
	// ServiceRules specifies that the rules are bound to services
	ServiceRules []PolycubeNetworkPolicyEgressServiceRuleContainer `json:"serviceRules,omitempty"`
}

// PolycubeNetworkPolicyIngressRule is an ingress rule
type PolycubeNetworkPolicyIngressRule struct {
	// From is the peer
	From PolycubeNetworkPolicyPeer `json:"from,omitempty"`
	// Protocol is the level 4 protocol
	Protocol PolycubeNetworkPolicyProtocol `json:"protocol,omitempty"`
	// Ports is the container of the ports
	Ports PolycubeNetworkPolicyPorts `json:"ports,omitempty"`
	// TCPFlags is a list of TCP flags
	TCPFlags []PolycubeNetworkPolicyTCPFlag `json:"tcpflags,omitempty"`
	// Action is the action to be taken
	Action PolycubeNetworkPolicyRuleAction `json:"action,omitempty"`
	// Description is the description of the rule
	Description string `json:"description,omitempty"`
}

// PolycubeNetworkPolicyIngressServiceRuleContainer contains rules bound to certain services
type PolycubeNetworkPolicyIngressServiceRuleContainer struct {
	// ApplyToServices is a list of services
	ApplyToServices []string `json:"applyToServices,omitempty"`
	// +optional
	// DropAll specifies to drop everything in ingress
	DropAll *bool `json:"dropAll,omitempty"`
	// +optional
	// AllowAll specifies to allow anyone in ingress
	AllowAll *bool `json:"allowAll,omitempty"`
	// +optional
	// Rules is a list of rules bound with the specified services
	Rules []PolycubeNetworkPolicyIngressServiceRule `json:"rules,omitempty"`
}

// PolycubeNetworkPolicyIngressServiceRule is the rules about certain service
type PolycubeNetworkPolicyIngressServiceRule struct {
	// From is the peer
	From PolycubeNetworkPolicyPeer `json:"from,omitempty"`
	// Action is the action to be taken
	Action PolycubeNetworkPolicyRuleAction `json:"action,omitempty"`
	// Description is the description of this rule
	Description string `json:"description,omitempty"`
	// TCPFlags is a list of TCP Flags
	TCPFlags []PolycubeNetworkPolicyTCPFlag `json:"tcpflags,omitempty"`
}

type PolycubeNetworkPolicyEgressRule struct {
	To          PolycubeNetworkPolicyPeer       `json:"to,omitempty"`
	Protocol    PolycubeNetworkPolicyProtocol   `json:"protocol,omitempty"`
	Ports       PolycubeNetworkPolicyPorts      `json:"ports,omitempty"`
	TCPFlags    []PolycubeNetworkPolicyTCPFlag  `json:"tcpflags,omitempty"`
	Action      PolycubeNetworkPolicyRuleAction `json:"action,omitempty"`
	Description string                          `json:"description,omitempty"`
}

// PolycubeNetworkPolicyEgressServiceRuleContainer contains rules bound to certain services
type PolycubeNetworkPolicyEgressServiceRuleContainer struct {
	// ApplyToServices is a list of services
	ApplyToServices []string `json:"applyToServices,omitempty"`
	// +optional
	// DropAll specifies to drop everything in egress
	DropAll *bool `json:"dropAll,omitempty"`
	// +optional
	// AllowAll specifies to allow anyone in egress
	AllowAll *bool `json:"allowAll,omitempty"`
	// +optional
	// Rules is a list of rules bound with the specified services
	Rules []PolycubeNetworkPolicyEgressServiceRule `json:"rules,omitempty"`
}

// PolycubeNetworkPolicyEgressServiceRule is the rules about certain service
type PolycubeNetworkPolicyEgressServiceRule struct {
	// From is the peer
	From PolycubeNetworkPolicyPeer `json:"from,omitempty"`
	// Action is the action to be taken
	Action PolycubeNetworkPolicyRuleAction `json:"action,omitempty"`
	// Description is the description of this rule
	Description string `json:"description,omitempty"`
	// TCPFlags is a list of TCP Flags
	TCPFlags []PolycubeNetworkPolicyTCPFlag `json:"tcpflags,omitempty"`
}

// PolycubeNetworkPolicyPeer contains data of the peer
type PolycubeNetworkPolicyPeer struct {
	// Peer is the peer type
	Peer PolycubeNetworkPolicyPeerObject `json:"peer,omitempty"`
	// +optional
	// Any tells if name and labels don't matter
	Any *bool `json:"any,omitempty"`
	// +optional
	// WithName specifies the name of the object. Only for Deployment
	WithName string `json:"withName,omitempty"`
	// +optional
	// WithLabels specifies the labels of the object. Only for Pod
	WithLabels map[string]string `json:"withLabels,omitempty"`
	// +optional
	// WithIP specifies the ip. Only for World
	WithIP PolycubeNetworkPolicyWithIP `json:"withIP,omitempty"`
	// +optional
	// OnNamespace specifies the namespaces of the peer. Only for Deployment, Pod
	OnNamespace PolycubeNetworkPolicyNamespaceSelector `json:"onNamespace,omitempty"`
}

// PolycubeNetworkPolicyWithIP is the IP container
type PolycubeNetworkPolicyWithIP struct {
	//	List is a list of IPs in CIDR notation
	List []string `json:"list,omitempty"`
	// +optional
	// Except is a list of IPs in CIDR Notation
	Except []string `json:"except,omitempty"`
}

// PolycubeNetworkPolicyPeerObject is the object peer
type PolycubeNetworkPolicyPeerObject string

const (
	// DeploymentPeer is the Deployment
	DeploymentPeer PolycubeNetworkPolicyTargetObject = "deployment"
	// PodPeer is the Pod
	PodPeer PolycubeNetworkPolicyTargetObject = "pod"
	// WorldPeer is the World
	WorldPeer PolycubeNetworkPolicyTargetObject = "world"
)

// PolycubeNetworkPolicyNamespaceSelector is a selector for namespaces
type PolycubeNetworkPolicyNamespaceSelector struct {
	// +optional
	// WithName is the name of the namespace
	WithName string `json:"withName,omitempty"`
	// +optional
	// WithLabels is the namespace's labels
	WithLabels map[string]string `json:"withLabels,omitempty"`
}

// PolycubeNetworkPolicyProtocol is the level 4 protocol
type PolycubeNetworkPolicyProtocol string

const (
	// TCP is TCP
	TCP PolycubeNetworkPolicyProtocol = "tcp"
	// UDP is UDP
	UDP PolycubeNetworkPolicyProtocol = "udp"
	// ICMP is ICMPv4
	ICMP PolycubeNetworkPolicyProtocol = "icmp"
)

// PolycubeNetworkPolicyPorts contains the ports
type PolycubeNetworkPolicyPorts struct {
	// +optional
	// Source is the source port
	Source int32 `json:"source,omitempty"`
	// Destination is the destination port
	Destination int32 `json:"destination,omitempty"`
}

// PolycubeNetworkPolicyTCPFlag is the TCP flag
type PolycubeNetworkPolicyTCPFlag string

const (
	// SYNFlag is SYN
	SYNFlag PolycubeNetworkPolicyTCPFlag = "SYN"
	// FINFlag is FIN
	FINFlag PolycubeNetworkPolicyTCPFlag = "FIN"
	// ACKFlag is ACK
	ACKFlag PolycubeNetworkPolicyTCPFlag = "ACK"
	// RSTFlag is RST
	RSTFlag PolycubeNetworkPolicyTCPFlag = "RST"
	// PSHFlag is PSH
	PSHFlag PolycubeNetworkPolicyTCPFlag = "PSH"
	// URGFlag is URG
	URGFlag PolycubeNetworkPolicyTCPFlag = "URG"
	// CWRFlag is CWR
	CWRFlag PolycubeNetworkPolicyTCPFlag = "CWR"
	// ECEFlag is ECE
	ECEFlag PolycubeNetworkPolicyTCPFlag = "ECE"
)

// PolycubeNetworkPolicyRuleAction is the action
type PolycubeNetworkPolicyRuleAction string

const (
	// DropAction is DROP
	DropAction PolycubeNetworkPolicyRuleAction = "drop"
	// AllowAction is Forward
	AllowAction PolycubeNetworkPolicyRuleAction = "forward"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PolycubeNetworkPolicyList contains a list of Network Policies.
type PolycubeNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `son:"metadata,omitempty"`
	// Items contains the network policies
	Items []PolycubeNetworkPolicy `json:"items"`
}
