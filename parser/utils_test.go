package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildIngress(t *testing.T) {
	src := "10.10.10.10"

	result := BuildIngressConnectionTemplates(src, "forward")

	for _, rule := range result.Egress {
		assert.Equal(t, rule.Src, src)
	}

	for _, rule := range result.Ingress {
		assert.Equal(t, rule.Dst, src)
	}
}
