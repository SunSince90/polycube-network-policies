package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/SunSince90/polycube-network-policies/controller"
	"github.com/SunSince90/polycube-network-policies/parser"
	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycubenetwork.com/v1beta"
	pnp_clientset "github.com/SunSince90/polycube-network-policies/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func getKubernetesClient() (kubernetes.Interface, pnp_clientset.Interface) {

	kubeconfig := os.Getenv("HOME") + "/.kube/config"

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	var err1 error
	clientset, err1 := kubernetes.NewForConfig(config)
	if err1 != nil {
		panic(err1.Error())
	}

	pnpclientset, err := pnp_clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	log.Info("Successfully constructed k8s client")
	return clientset, pnpclientset
}

func main() {
	log.Infoln("Hello, World!")

	kclientset, pclientset := getKubernetesClient()
	p := controller.NewPodController(kclientset)
	s := controller.NewServiceController(kclientset)

	// use a channel to synchronize the finalization for a graceful shutdown
	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go p.Run()
	go s.Run()
	parser := parser.NewPolycubePolicyParser(p, s)
	c := controller.NewPcnPolicyController(kclientset, pclientset)
	go c.Run(stopCh)
	c.AddUpdateFunc("new", func(item interface{}) {
		policy, ok := item.(*v1beta.PolycubeNetworkPolicy)
		if !ok {
			log.Errorln("Error in casting policy!")
		}

		ingressRules, egressRules := parser.ParseRules(policy.Spec.IngressRules, policy.Spec.EngressRules, policy.Namespace)

		log.Println("--- Parsed Ingress ---")
		for _, policyRule := range ingressRules {
			log.Println("- egress rules")
			for _, rule := range policyRule.Egress {
				log.Printf("-- %+v\n", rule)
			}
			log.Println("- ingress rules")
			for _, rule := range policyRule.Ingress {
				log.Printf("-- %+v\n", rule)
			}
		}
		log.Println("--- Parsed Egress ---")
		for _, policyRule := range egressRules {
			log.Println("- egress rules")
			for _, rule := range policyRule.Egress {
				log.Printf("-- %+v\n", rule)
			}
			log.Println("- ingress rules")
			for _, rule := range policyRule.Ingress {
				log.Printf("-- %+v\n", rule)
			}
		}

	})

	// use a channel to handle OS signals to terminate and gracefully shut
	// down processing
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm

	p.Stop()
	s.Stop()
}
