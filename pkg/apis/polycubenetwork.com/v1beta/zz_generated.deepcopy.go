// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1beta

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicy) DeepCopyInto(out *PolycubeNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.ApplyTo.DeepCopyInto(&out.ApplyTo)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicy.
func (in *PolycubeNetworkPolicy) DeepCopy() *PolycubeNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolycubeNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyEgressRule) DeepCopyInto(out *PolycubeNetworkPolicyEgressRule) {
	*out = *in
	in.To.DeepCopyInto(&out.To)
	out.Ports = in.Ports
	if in.TCPFlags != nil {
		in, out := &in.TCPFlags, &out.TCPFlags
		*out = make([]PolycubeNetworkPolicyTCPFlag, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyEgressRule.
func (in *PolycubeNetworkPolicyEgressRule) DeepCopy() *PolycubeNetworkPolicyEgressRule {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyEgressRuleContainer) DeepCopyInto(out *PolycubeNetworkPolicyEgressRuleContainer) {
	*out = *in
	if in.DropAll != nil {
		in, out := &in.DropAll, &out.DropAll
		*out = new(bool)
		**out = **in
	}
	if in.AllowAll != nil {
		in, out := &in.AllowAll, &out.AllowAll
		*out = new(bool)
		**out = **in
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]PolycubeNetworkPolicyEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyEgressRuleContainer.
func (in *PolycubeNetworkPolicyEgressRuleContainer) DeepCopy() *PolycubeNetworkPolicyEgressRuleContainer {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyEgressRuleContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyIngressRule) DeepCopyInto(out *PolycubeNetworkPolicyIngressRule) {
	*out = *in
	in.From.DeepCopyInto(&out.From)
	if in.Protocols != nil {
		in, out := &in.Protocols, &out.Protocols
		*out = make([]PolycubeNetworkPolicyProtocolContainer, len(*in))
		copy(*out, *in)
	}
	if in.TCPFlags != nil {
		in, out := &in.TCPFlags, &out.TCPFlags
		*out = make([]PolycubeNetworkPolicyTCPFlag, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyIngressRule.
func (in *PolycubeNetworkPolicyIngressRule) DeepCopy() *PolycubeNetworkPolicyIngressRule {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyIngressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyIngressRuleContainer) DeepCopyInto(out *PolycubeNetworkPolicyIngressRuleContainer) {
	*out = *in
	if in.DropAll != nil {
		in, out := &in.DropAll, &out.DropAll
		*out = new(bool)
		**out = **in
	}
	if in.AllowAll != nil {
		in, out := &in.AllowAll, &out.AllowAll
		*out = new(bool)
		**out = **in
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]PolycubeNetworkPolicyIngressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyIngressRuleContainer.
func (in *PolycubeNetworkPolicyIngressRuleContainer) DeepCopy() *PolycubeNetworkPolicyIngressRuleContainer {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyIngressRuleContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyList) DeepCopyInto(out *PolycubeNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]PolycubeNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyList.
func (in *PolycubeNetworkPolicyList) DeepCopy() *PolycubeNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolycubeNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyNamespaceSelector) DeepCopyInto(out *PolycubeNetworkPolicyNamespaceSelector) {
	*out = *in
	if in.WithLabels != nil {
		in, out := &in.WithLabels, &out.WithLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Any != nil {
		in, out := &in.Any, &out.Any
		*out = new(bool)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyNamespaceSelector.
func (in *PolycubeNetworkPolicyNamespaceSelector) DeepCopy() *PolycubeNetworkPolicyNamespaceSelector {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyNamespaceSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyPeer) DeepCopyInto(out *PolycubeNetworkPolicyPeer) {
	*out = *in
	if in.Any != nil {
		in, out := &in.Any, &out.Any
		*out = new(bool)
		**out = **in
	}
	if in.WithLabels != nil {
		in, out := &in.WithLabels, &out.WithLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	in.WithIP.DeepCopyInto(&out.WithIP)
	if in.OnNamespace != nil {
		in, out := &in.OnNamespace, &out.OnNamespace
		*out = new(PolycubeNetworkPolicyNamespaceSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyPeer.
func (in *PolycubeNetworkPolicyPeer) DeepCopy() *PolycubeNetworkPolicyPeer {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyPeer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyPorts) DeepCopyInto(out *PolycubeNetworkPolicyPorts) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyPorts.
func (in *PolycubeNetworkPolicyPorts) DeepCopy() *PolycubeNetworkPolicyPorts {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyPorts)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyProtocolContainer) DeepCopyInto(out *PolycubeNetworkPolicyProtocolContainer) {
	*out = *in
	out.Ports = in.Ports
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyProtocolContainer.
func (in *PolycubeNetworkPolicyProtocolContainer) DeepCopy() *PolycubeNetworkPolicyProtocolContainer {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyProtocolContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicySpec) DeepCopyInto(out *PolycubeNetworkPolicySpec) {
	*out = *in
	in.IngressRules.DeepCopyInto(&out.IngressRules)
	in.EngressRules.DeepCopyInto(&out.EngressRules)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicySpec.
func (in *PolycubeNetworkPolicySpec) DeepCopy() *PolycubeNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyTarget) DeepCopyInto(out *PolycubeNetworkPolicyTarget) {
	*out = *in
	if in.Any != nil {
		in, out := &in.Any, &out.Any
		*out = new(bool)
		**out = **in
	}
	if in.WithLabels != nil {
		in, out := &in.WithLabels, &out.WithLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyTarget.
func (in *PolycubeNetworkPolicyTarget) DeepCopy() *PolycubeNetworkPolicyTarget {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyTarget)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolycubeNetworkPolicyWithIP) DeepCopyInto(out *PolycubeNetworkPolicyWithIP) {
	*out = *in
	if in.List != nil {
		in, out := &in.List, &out.List
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolycubeNetworkPolicyWithIP.
func (in *PolycubeNetworkPolicyWithIP) DeepCopy() *PolycubeNetworkPolicyWithIP {
	if in == nil {
		return nil
	}
	out := new(PolycubeNetworkPolicyWithIP)
	in.DeepCopyInto(out)
	return out
}
