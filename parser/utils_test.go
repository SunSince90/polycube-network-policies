package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildIngress(t *testing.T) {
	src := "10.10.10.10"

	// --- First case: forward
	result := buildIngressConnectionTemplates(src, "forward")

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
	result = buildIngressConnectionTemplates(src, "drop")

	assert.Empty(t, result.Ingress)
	assert.Len(t, result.Egress, 1)

	assert.Equal(t, "drop", result.Egress[0].Action)
	assert.Equal(t, src, result.Egress[0].Src)
	assert.Equal(t, "new", result.Egress[0].Conntrack)
}

func TestBuildEgress(t *testing.T) {
	dst := "10.10.10.10"

	// --- First case: forward
	result := buildEgressConnectionTemplates(dst, "forward")

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
	result = buildEgressConnectionTemplates(dst, "drop")

	assert.Empty(t, result.Egress)
	assert.Len(t, result.Ingress, 1)

	assert.Equal(t, "drop", result.Ingress[0].Action)
	assert.Equal(t, dst, result.Ingress[0].Dst)
	assert.Equal(t, "new", result.Ingress[0].Conntrack)
}
