package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/SunSince90/polycube-network-policies/controller"
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
	c := controller.NewPcnPolicyController(kclientset, pclientset)

	// use a channel to synchronize the finalization for a graceful shutdown
	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go c.Run(stopCh)

	// use a channel to handle OS signals to terminate and gracefully shut
	// down processing
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}
