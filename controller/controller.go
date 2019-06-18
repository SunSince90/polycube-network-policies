package controller

import (
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	pnp_clientset "github.com/SunSince90/polycube-network-policies/pkg/client/clientset/versioned"
	pnp_informer "github.com/SunSince90/polycube-network-policies/pkg/client/informers/externalversions/polycubenetwork.com/v1beta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// Controller struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching)
// queueing, and handling of resource changes
type PcnPolicyController struct {
	logger     *log.Entry
	kclientset kubernetes.Interface
	queue      workqueue.RateLimitingInterface
	informer   cache.SharedIndexInformer
	upd        func(interface{})
	new        func(interface{})
	del        func(interface{})
	//handler    Handler
}

func NewPcnPolicyController(kclientset kubernetes.Interface, pclientset pnp_clientset.Interface) *PcnPolicyController {

	log.NewEntry(log.New())
	log.Infoln("hello from the controller")

	// retrieve our custom resource informer which was generated from
	// the code generator and pass it the custom resource client, specifying
	// we should be looking through all namespaces for listing and watching
	informer := pnp_informer.NewPolycubeNetworkPolicyInformer(
		pclientset,
		meta_v1.NamespaceAll,
		0,
		cache.Indexers{},
	)

	// create a new queue so that when the informer gets a resource that is either
	// a result of listing or watching, we can add an idenfitying key to the queue
	// so that it can be handled in the handler
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// add event handlers to handle the three types of events for resources:
	//  - adding new resources
	//  - updating existing resources
	//  - deleting resources
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// convert the resource object into a key (in this case
			// we are just doing it in the format of 'namespace/name')
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Infof("Add myresource: %s", key)
			if err == nil {
				// add the key to the queue for the handler to get
				queue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			log.Infof("Update myresource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// DeletionHandlingMetaNamsespaceKeyFunc is a helper function that allows
			// us to check the DeletedFinalStateUnknown existence in the event that
			// a resource was deleted but it is still contained in the index
			//
			// this then in turn calls MetaNamespaceKeyFunc
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			log.Infof("Delete myresource: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	// construct the Controller object which has all of the necessary components to
	// handle logging, connections, informing (listing and watching), the queue,
	// and the handler
	controller := PcnPolicyController{
		logger:     log.NewEntry(log.New()),
		kclientset: kclientset,
		informer:   informer,
		queue:      queue,
		//handler:   &TestHandler{},
	}

	return &controller
}

func (c *PcnPolicyController) AddUpdateFunc(t string, temp func(interface{})) {
	switch t {
	default:
	case "new":
		c.new = temp
	case "update":
		c.upd = temp
	case "del":
		c.del = temp
	}
}

// Run is the main path of execution for the controller loop
func (c *PcnPolicyController) Run(stopCh <-chan struct{}) {
	// handle a panic with logging and exiting
	defer utilruntime.HandleCrash()
	// ignore new items in the queue but when all goroutines
	// have completed existing items then shutdown
	defer c.queue.ShutDown()

	c.logger.Info("Controller.Run: initiating")

	// run the informer to start listing and watching resources
	go c.informer.Run(stopCh)

	// do the initial synchronization (one time) to populate resources
	if !cache.WaitForCacheSync(stopCh, c.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Error syncing cache"))
		return
	}
	c.logger.Info("Controller.Run: cache sync complete")

	// run the runWorker method every second with a stop channel
	wait.Until(c.runWorker, time.Second, stopCh)
}

// HasSynced allows us to satisfy the Controller interface
// by wiring up the informer's HasSynced method to it
func (c *PcnPolicyController) HasSynced() bool {
	return c.informer.HasSynced()
}

// runWorker executes the loop to process new items added to the queue
func (c *PcnPolicyController) runWorker() {
	log.Info("Controller.runWorker: starting")

	// invoke processNextItem to fetch and consume the next change
	// to a watched or listed resource
	for c.processNextItem() {
		log.Info("Controller.runWorker: processing next item")
	}

	log.Info("Controller.runWorker: completed")
}

// processNextItem retrieves each queued item and takes the
// necessary handler action based off of if the item was
// created or deleted
func (c *PcnPolicyController) processNextItem() bool {
	log.Info("Controller.processNextItem: start")

	// fetch the next item (blocking) from the queue to process or
	// if a shutdown is requested then return out of this to stop
	// processing
	key, quit := c.queue.Get()

	// stop the worker loop from running as this indicates we
	// have sent a shutdown message that the queue has indicated
	// from the Get method
	if quit {
		return false
	}

	defer c.queue.Done(key)

	// assert the string out of the key (format `namespace/name`)
	keyRaw := key.(string)

	// take the string key and get the object out of the indexer
	//
	// item will contain the complex object for the resource and
	// exists is a bool that'll indicate whether or not the
	// resource was created (true) or deleted (false)
	//
	// if there is an error in getting the key from the index
	// then we want to retry this particular queue key a certain
	// number of times (5 here) before we forget the queue key
	// and throw an error
	item, exists, err := c.informer.GetIndexer().GetByKey(keyRaw)
	if err != nil {
		if c.queue.NumRequeues(key) < 5 {
			c.logger.Errorf("Controller.processNextItem: Failed processing item with key %s with error %v, retrying", key, err)
			c.queue.AddRateLimited(key)
		} else {
			c.logger.Errorf("Controller.processNextItem: Failed processing item with key %s with error %v, no more retries", key, err)
			c.queue.Forget(key)
			utilruntime.HandleError(err)
		}
	}

	// if the item doesn't exist then it was deleted and we need to fire off the handler's
	// ObjectDeleted method. but if the object does exist that indicates that the object
	// was created (or updated) so run the ObjectCreated method
	//
	// after both instances, we want to forget the key from the queue, as this indicates
	// a code path of successful queue key processing
	if !exists {
		c.logger.Infof("Controller.processNextItem: object deleted detected: %s", keyRaw)
		if c.new != nil {
			c.new(item)
		}
		c.queue.Forget(key)
	} else {
		c.logger.Infof("Controller.processNextItem: object created detected: %s", keyRaw)
		if c.new != nil {
			c.new(item)
		}
		c.queue.Forget(key)
	}

	// keep the worker loop running by returning true
	return true
}

/*func (c *PcnPolicyController) treatObject(temp interface{}) {
	policy, ok := temp.(*v1beta.PolycubeNetworkPolicy)
	if !ok {
		log.Errorln("Error in casting policy!")
	}

	log.Printf("%+v\n", policy)

	p := parser.NewPolycubePolicyParser(c.kclientset, nil)
}*/
