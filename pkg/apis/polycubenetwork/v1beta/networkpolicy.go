package v1beta

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicy is a network policy handled by polycube
type NetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Status NetworkPolicyStatus `json:"status,omitempty"`
	// Spec of this policy
	Spec NetworkPolicySpec `json:"spec,omitempty"`
}

// NetworkPolicySpec contains the specifications of this Network Policy
type NetworkPolicySpec struct {
	Message string `json:"message,omitempty"`
}

// NetworkPolicyStatus defines the status of this network policy
type NetworkPolicyStatus struct {
	Name string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyList contains a list of Network Policies.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `son:"metadata,omitempty"`
	// Items contains the network policies
	Items []NetworkPolicy `json:"items"`
}
