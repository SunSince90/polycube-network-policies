package main

import (
	"os"
	"os/signal"
	"syscall"

	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"
	core_v1 "k8s.io/api/core/v1"

	log "github.com/Sirupsen/logrus"

	"github.com/SunSince90/polycube-network-policies/controller"
	v1beta_parser "github.com/SunSince90/polycube-network-policies/parser"
	"github.com/SunSince90/polycube-network-policies/pkg/apis/polycube.network/v1beta"
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
	parser := v1beta_parser.NewPolycubePolicyParser(p, s)
	c := controller.NewPcnPolicyController(kclientset, pclientset)
	go c.Run(stopCh)
	c.AddUpdateFunc("new", func(item interface{}) {
		policy, ok := item.(*v1beta.PolycubeNetworkPolicy)
		if !ok {
			log.Errorln("Error in casting policy!")
		}

		ingressRules, egressRules, ingressActions, egressActions := parser.ParseRules(policy.ApplyTo, policy.Spec.IngressRules, policy.Spec.EngressRules, policy.Namespace)

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

		log.Println("--- Ingress Actions ---")
		for _, actions := range ingressActions {
			for _, action := range actions {
				log.Printf("- %+v\n", action)
			}
		}
		log.Println("--- Egress Actions ---")
		for _, actions := range egressActions {
			for _, action := range actions {
				log.Printf("- %+v\n", action)
			}
		}

		//	Service subscriptions
		if policy.ApplyTo.Target == v1beta.ServiceTarget {
			log.Println("Going to subscribe to changes to service", policy.ApplyTo.WithName, "on namespace", policy.Namespace)
			queryS := v1beta_parser.BuildServiceQuery(policy.ApplyTo.WithName, false)
			queryN := v1beta_parser.BuildNamespaceQuery(policy.Namespace, nil, false)

			//	Even for new services
			s.Subscribe(pcn_types.Update, queryS, queryN, func(service *core_v1.Service) {
				log.Println("policy with name", policy.Name, "should be undeployed and redeployed again.")
				//	Cease with (subs=true)
			})
			/*s.Subscribe(pcn_types.Delete, queryS, queryN, func(service *core_v1.Service) {
				log.Println("policy with name", policy.Name, "should be undeployed.")
				//	cease with (subs=true)
			})*/
		}

		//	Ingress actions
		for i, actions := range ingressActions {
			policyRuleName := policy.Name + "#" + string(i) + "i"
			for _, action := range actions {

				//	Build the namespace query:
				//	If the user specifies to target peers on namespaces with certain labels, then we need to subscribe to them!
				//	These are bad practices and probably even rare ones, but if a user puts a label to a namespace then we need to select those pods as well!
				//	Same thing if the labels are removed!
				queryN := pcn_types.ObjectQuery{}
				if len(action.NamespaceName) < 1 || (len(action.NamespaceName) > 0 && action.NamespaceName != "*") {
					queryN = v1beta_parser.BuildNamespaceQuery("", action.NamespaceLabels, false)
					log.Println("Going to subscribe to updates to namespaces for", policyRuleName, queryN)

					//	On update
					//	What changed?
					//	-> look at the labels of it
					//	If the labels changed, then remove and re-deploy
				}
			}
		}

		//	Egress namespace actions
		for i, actions := range egressActions {
			policyRuleName := policy.Name + "#" + string(i) + "e"
			for _, action := range actions {

				//	Build the namespace query:
				//	If the user specifies to target peers on namespaces with certain labels, then we need to subscribe to them!
				//	These are bad practices and probably even rare ones, but if a user puts a label to a namespace then we need to select those pods as well!
				//	Same thing if the labels are removed!
				queryN := pcn_types.ObjectQuery{}
				if len(action.NamespaceName) < 1 || (len(action.NamespaceName) > 0 && action.NamespaceName != "*") {
					queryN = v1beta_parser.BuildNamespaceQuery("", action.NamespaceLabels, false)
					log.Println("Going to subscribe to updates to namespaces for", policyRuleName, queryN)

					//	On update
					//	What changed?
					//	-> look at the labels of it
					//	If the labels changed, then remove and re-deploy
				}
			}
		}

		//	Egress service subscription
		if len(policy.Spec.EngressRules.Rules) > 0 {
			for i, peer := range policy.Spec.EngressRules.Rules {
				policyRuleName := policy.Name + "#" + string(i) + "e"

				if peer.To.Peer == v1beta.ServicePeer {
					queryS := v1beta_parser.BuildServiceQuery(peer.To.WithName, false)

					//	Defaulting the namespace
					if peer.To.OnNamespace == nil {
						peer.To.OnNamespace = &v1beta.PolycubeNetworkPolicyNamespaceSelector{
							WithNames: []string{policy.Namespace},
						}
					}
					anyNs := (peer.To.OnNamespace.Any != nil && *peer.To.OnNamespace.Any == true)

					//	On namespaces with name?
					if len(peer.To.OnNamespace.WithNames) > 0 {
						for _, ns := range peer.To.OnNamespace.WithNames {
							queryN := v1beta_parser.BuildNamespaceQuery(ns, nil, false)

							//	updates
							s.Subscribe(pcn_types.Update, queryS, queryN, func(service *core_v1.Service) {
								//	Just undeploy this rule and redeploy
								log.Println("undeploy and redeploy", policyRuleName)
							})

							//	deletes
							s.Subscribe(pcn_types.Delete, queryS, queryN, func(service *core_v1.Service) {
								//	Just undeploy this rule
								log.Println("delete", policyRuleName)
							})

							//	New
							s.Subscribe(pcn_types.Delete, queryS, queryN, func(service *core_v1.Service) {
								//	parse and deploy this rule
								log.Println("deploy", policyRuleName)
							})
						}
					} else {
						queryN := v1beta_parser.BuildNamespaceQuery("", peer.To.OnNamespace.WithLabels, anyNs)

						//	updates
						s.Subscribe(pcn_types.Update, queryS, queryN, func(service *core_v1.Service) {
							//	Just undeploy this rule and redeploy
						})

						//	deletes
						s.Subscribe(pcn_types.Delete, queryS, queryN, func(service *core_v1.Service) {
							//	Just undeploy this rule
						})

						//	New
						s.Subscribe(pcn_types.Delete, queryS, queryN, func(service *core_v1.Service) {
							//	parse and deploy this rule
						})
					}

					//	TODO: update subscriptions for namespace labels
				}
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
