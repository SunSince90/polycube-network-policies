package main

import (
	"fmt"

	log "github.com/Sirupsen/logrus"

	"github.com/SunSince90/polycube-network-policies/controller"
	pnp_clientset "github.com/SunSince90/polycube-network-policies/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func getKubernetesClient() (kubernetes.Interface, pnp_clientset.Interface) {

	kubeconfig := "/var/lib/pcn_k8s/kubeconfig.conf"

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
	fmt.Println("Hello, World!")

	kclientset, _ := getKubernetesClient()

	//	Set up the network policy controller (for the kubernetes policies)
	//defaultnpc = pcn_controllers.NewDefaultNetworkPolicyController(nodeName, clientset)

	controller.NewPcnPolicyController(kclientset)
}
