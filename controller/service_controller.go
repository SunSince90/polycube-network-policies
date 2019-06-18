package controller

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	//	TODO-ON-MERGE: change the path to polycube
	pcn_types "github.com/SunSince90/polycube/src/components/k8s/pcn_k8s/types"

	log "github.com/Sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	typed_core_v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	workqueue "k8s.io/client-go/util/workqueue"
)

// ServiceController is the interface of the service controller
type ServiceController interface {
	Run()
	Stop()
	Subscribe(pcn_types.EventType, pcn_types.ObjectQuery, pcn_types.ObjectQuery, func(*core_v1.Service)) (func(), error)
	GetServices(pcn_types.ObjectQuery, pcn_types.ObjectQuery) ([]core_v1.Service, error)
}

// PcnServiceController is the implementation of the Service controller
type PcnServiceController struct {
	clientset   kubernetes.Interface
	queue       workqueue.RateLimitingInterface
	informer    cache.SharedIndexInformer
	startedOn   time.Time
	dispatchers EventDispatchersContainer
	stopCh      chan struct{}
	maxRetries  int
	logBy       string
	lock        sync.Mutex
	nsInterface typed_core_v1.NamespaceInterface
}

// NewServiceController will start a new Service controller
func NewServiceController(clientset kubernetes.Interface) ServiceController {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": "Service Controller", "method": "NewServiceController()"})

	logBy := "ServiceController"
	maxRetries := 5

	//------------------------------------------------
	//	Set up the Service Controller
	//------------------------------------------------

	informer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
			return clientset.CoreV1().Services(meta_v1.NamespaceAll).List(options)
		},
		WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().Services(meta_v1.NamespaceAll).Watch(options)
		},
	},
		&core_v1.Service{},
		0, //Skip resync
		cache.Indexers{},
	)

	//------------------------------------------------
	//	Set up the queue
	//------------------------------------------------

	//	Start the queue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	//------------------------------------------------
	//	Set up the event handlers
	//------------------------------------------------

	//	Whenever something happens to network policies, the event is routed by this event handler and routed to the queue. It'll know what to do.
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event, err := buildEvent(obj, pcn_types.New)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}
			queue.Add(event)
		},
		UpdateFunc: func(old, new interface{}) {
			event, err := buildEvent(new, pcn_types.Update)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}

			queue.Add(event)
		},
		DeleteFunc: func(obj interface{}) {
			event, err := buildEvent(obj, pcn_types.Delete)
			if err != nil {
				utilruntime.HandleError(err)
				return
			}

			queue.Add(event)
		},
	})

	//------------------------------------------------
	//	Set up the dispatchers
	//------------------------------------------------

	dispatchers := EventDispatchersContainer{
		new:    NewEventDispatcher("new-service-event-dispatcher"),
		update: NewEventDispatcher("update-service-event-dispatcher"),
		delete: NewEventDispatcher("delete-service-event-dispatcher"),
	}

	//	If namespace controller is nil, we're going to use it like this.
	var nsInterface typed_core_v1.NamespaceInterface
	//if nsController == nil {
	l.Infoln("No namespace controller provided. Going to use a light implementation.")
	nsInterface = clientset.CoreV1().Namespaces()
	//}

	//	Everything set up, return the controller
	return &PcnServiceController{
		//nsController: nsController,
		clientset:   clientset,
		queue:       queue,
		informer:    informer,
		dispatchers: dispatchers,
		logBy:       logBy,
		maxRetries:  maxRetries,
		stopCh:      make(chan struct{}),
		nsInterface: nsInterface,
	}
}

// Run starts the service controller
func (s *PcnServiceController) Run() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": s.logBy, "method": "Run()"})

	//	Don't let panics crash the process
	defer utilruntime.HandleCrash()

	//	Record when we started, it is going to be used later
	s.startedOn = time.Now().UTC()

	//	Let's go!
	go s.informer.Run(s.stopCh)

	//	Make sure the cache is populated
	if !cache.WaitForCacheSync(s.stopCh, s.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	l.Infoln("Started...")

	//	Work *until* something bad happens. If that's the case, wait one second and then re-work again.
	//	Well, except when someone tells us to stop... in that case, just stop, man
	wait.Until(s.work, time.Second, s.stopCh)
}

// work gets the item from the queue and attempts to process it
func (s *PcnServiceController) work() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": s.logBy, "method": "work()"})
	stop := false

	for !stop {

		//	Get the item's key from the queue
		_event, quit := s.queue.Get()

		if quit {
			l.Infoln("Quit requested... worker going to exit.")
			return
		}

		event, ok := _event.(pcn_types.Event)
		if ok {
			err := s.process(event)

			//	No errors?
			if err == nil {
				//	Then reset the ratelimit counters
				s.queue.Forget(_event)
			} else if s.queue.NumRequeues(_event) < s.maxRetries {
				//	Tried less than the maximum retries?
				l.Warningf("Error processing item with key %s (will retry): %v", event.Key, err)
				s.queue.AddRateLimited(_event)
			} else {
				//	Too many retries?
				l.Errorf("Error processing %s (giving up): %v", event.Key, err)
				s.queue.Forget(_event)
				utilruntime.HandleError(err)
			}
		} else {
			//	Don't process something which is not valid.
			s.queue.Forget(_event)
			utilruntime.HandleError(fmt.Errorf("Error when trying to parse event %#v from the queue", _event))
		}

		stop = quit
	}
}

// process will process the event and dispatch the pod
func (s *PcnServiceController) process(event pcn_types.Event) error {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": s.logBy, "method": "process()"})

	var service *core_v1.Service
	defer s.queue.Done(event)

	//	Get the service by querying the key that kubernetes has assigned to this in its cache
	_service, _, err := s.informer.GetIndexer().GetByKey(event.Key)

	//	Errors?
	if err != nil {
		l.Errorf("An error occurred: cannot find cache element with key %s from store %v", event.Key, err)
		return fmt.Errorf("An error occurred: cannot find cache element with key %s from ", event.Key)
	}

	//	Get the service or try to recover it.
	service, ok := _service.(*core_v1.Service)
	if !ok {
		service, ok = event.Object.(*core_v1.Service)
		if !ok {
			tombstone, ok := event.Object.(cache.DeletedFinalStateUnknown)
			if !ok {
				l.Errorln("error decoding object, invalid type")
				utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
				return fmt.Errorf("error decoding object, invalid type")
			}
			service, ok = tombstone.Obj.(*core_v1.Service)
			if !ok {
				l.Errorln("error decoding object tombstone, invalid type")
				utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
				return fmt.Errorf("error decoding object tombstone, invalid type")
			}
			l.Infof("Recovered deleted object '%s' from tombstone", service.GetName())
		}
	}

	//-------------------------------------
	//	Dispatch the event
	//-------------------------------------

	switch event.Type {

	case pcn_types.New:
		s.dispatchers.new.Dispatch(service)
	case pcn_types.Update:
		s.dispatchers.update.Dispatch(service)
	case pcn_types.Delete:
		s.dispatchers.delete.Dispatch(service)
	}

	return nil
}

// Stop will stop the service controller
func (s *PcnServiceController) Stop() {
	l := log.NewEntry(log.New())
	l.WithFields(log.Fields{"by": s.logBy, "method": "Stop()"})

	//	Make them know that exit has been requested
	close(s.stopCh)

	//	Shutdown the queue, making the worker unblock
	s.queue.ShutDown()

	//	Clean up the dispatchers
	s.dispatchers.new.CleanUp()
	s.dispatchers.update.CleanUp()
	s.dispatchers.delete.CleanUp()
}

// Subscribe executes the function consumer when the event event is triggered. It returns an error if the event type does not exist.
// It returns a function to call when you want to stop tracking that event.
func (s *PcnServiceController) Subscribe(event pcn_types.EventType, spec pcn_types.ObjectQuery, namespace pcn_types.ObjectQuery, consumer func(*core_v1.Service)) (func(), error) {

	//	Prepare the function to be executed
	consumerFunc := (func(item interface{}) {

		//	First, cast the item to a service, so that the consumer will receive exactly what it wants...
		service := item.(*core_v1.Service)

		//	Does this pod satisfies the conditions?
		if !s.serviceMeetsCriteria(service, spec, namespace) {
			return
		}

		//	Then, execute the consumer in a separate thread.
		//	NOTE: this step can also be done in the event dispatcher, but I want it to make them oblivious of the type they're handling.
		//	This way, the event dispatcher is as general as possible (also, it is not their concern to cast objects.)
		go consumer(service)
	})

	//	What event are you subscribing to?
	switch event {

	//-------------------------------------
	//	New event
	//-------------------------------------

	case pcn_types.New:
		id := s.dispatchers.new.Add(consumerFunc)

		return func() {
			s.dispatchers.new.Remove(id)
		}, nil

	//-------------------------------------
	//	Update event
	//-------------------------------------

	case pcn_types.Update:
		id := s.dispatchers.update.Add(consumerFunc)

		return func() {
			s.dispatchers.update.Remove(id)
		}, nil

	//-------------------------------------
	//	Delete Event
	//-------------------------------------

	case pcn_types.Delete:
		id := s.dispatchers.delete.Add(consumerFunc)

		return func() {
			s.dispatchers.delete.Remove(id)
		}, nil

	//-------------------------------------
	//	Undefined event
	//-------------------------------------

	default:
		return nil, fmt.Errorf("Undefined event type")
	}
}

// serviceMeetsCriteria is called when before dispatching the event to verify if the service should be dispatched or not
func (s *PcnServiceController) serviceMeetsCriteria(service *core_v1.Service, spec pcn_types.ObjectQuery, nsSpec pcn_types.ObjectQuery) bool {
	//	This is actually useless but who knows....
	if service == nil {
		return false
	}

	//-------------------------------------
	//	The namespace
	//-------------------------------------
	if len(nsSpec.Name) > 0 {
		if nsSpec.Name != "*" && service.Namespace != nsSpec.Name {
			return false
		}
	} else {
		//	Check the labels of the namespace
		if len(nsSpec.Labels) > 0 {
			// Get the list
			nsList, err := s.getNamespaces(pcn_types.ObjectQuery{
				By:     "labels",
				Labels: nsSpec.Labels,
			})
			if err != nil {
				return false
			}

			found := false
			for _, n := range nsList {
				if n.Name == service.Namespace {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	log.Println("after namespace")

	//-------------------------------------
	//	The Service
	//-------------------------------------

	// The name
	if len(spec.Name) > 0 {
		if spec.Name != "*" && service.Name != spec.Name {
			return false
		}

		return true
	}

	log.Println("after namespace")

	// The selectors
	if len(spec.Labels) > 0 {
		labelsFound := 0
		labelsToFind := len(spec.Labels)

		for neededKey, neededValue := range spec.Labels {
			if value, exists := service.Spec.Selector[neededKey]; exists && value == neededValue {
				labelsFound++
				if labelsFound == labelsToFind {
					break
				}
			} else {
				//	I didn't find this key or the value wasn't the one I wanted: it's pointless to go on checking the other labels.
				break
			}
		}

		//	Did we find all labels we needed?
		if labelsFound != labelsToFind {
			return false
		}
	}
	log.Println("after labels")

	return true
}

// GetServices gets services according to a specific service query and a namespace query
func (s *PcnServiceController) GetServices(queryService pcn_types.ObjectQuery, queryNs pcn_types.ObjectQuery) ([]core_v1.Service, error) {
	//	The namespaces the services must be found on
	//	If this remains empty it means that I don't care about the namespace they are in.
	ns := map[string]bool{}

	//------------------------------------------------
	//	Preliminary checks
	//------------------------------------------------
	//	The namespace
	if strings.ToLower(queryNs.By) == "name" && queryNs.Name != "*" {
		nsList, err := s.getNamespaces(queryNs)
		if err != nil {
			return []core_v1.Service{}, err
		}
		if len(nsList) < 1 {
			//	If no namespace is found, it is useless to go on searching for services
			return []core_v1.Service{}, nil
		}
		for _, n := range nsList {
			ns[n.Name] = true
		}
	}

	//	Helper function
	getAndFilter := func(listOptions meta_v1.ListOptions) ([]core_v1.Service, error) {
		list := []core_v1.Service{}

		//	Do I care or not about the namespace?
		//	If not, I'll put the NamespaceAll inside the map as its only value
		if len(ns) < 1 {
			ns[meta_v1.NamespaceAll] = true
		}

		//	Loop through all interested namespaces
		for namespace := range ns {
			lister, err := s.clientset.CoreV1().Services(namespace).List(listOptions)
			if err == nil {
				list = append(list, lister.Items...)
			} else {
				//return []core_v1.Service, err
				//	Just skip this namespace.
			}
		}
		return list, nil
	}

	//-------------------------------------
	//	Find by name
	//-------------------------------------

	byName := func(name string) ([]core_v1.Service, error) {
		if len(name) < 1 {
			return []core_v1.Service{}, errors.New("Service name not provided")
		}

		listOptions := meta_v1.ListOptions{}
		if name != "*" {
			listOptions.FieldSelector = "metadata.name=" + name
		}

		return getAndFilter(listOptions)
	}

	//-------------------------------------
	//	Find by labels
	//-------------------------------------

	byLabels := func(labels map[string]string) ([]core_v1.Service, error) {
		if labels == nil {
			return []core_v1.Service{}, errors.New("Service labels is nil")
		}
		if len(labels) < 1 {
			//	If you need to get all services, use get by name and name *
			return []core_v1.Service{}, errors.New("No service labels provided")
		}

		listOptions := meta_v1.ListOptions{
			LabelSelector: implodeLabels(labels),
		}

		return getAndFilter(listOptions)
	}

	switch strings.ToLower(queryService.By) {
	case "name":
		return byName(queryService.Name)
	case "labels":
		return byLabels(queryService.Labels)
	default:
		return []core_v1.Service{}, errors.New("Unrecognized service query")
	}
}

// getNamespaces gets the namespaces based on the provided query
func (s *PcnServiceController) getNamespaces(query pcn_types.ObjectQuery) ([]core_v1.Namespace, error) {

	// Use the external namespace controller, if available
	/*if p.nsController != nil {
		return p.nsController.GetNamespaces(query)
	}*/

	//-------------------------------------
	//	Find by name
	//-------------------------------------

	byName := func(name string) ([]core_v1.Namespace, error) {
		if len(name) < 1 {
			return []core_v1.Namespace{}, errors.New("Namespace name not provided")
		}

		listOptions := meta_v1.ListOptions{}
		if name != "*" {
			listOptions.FieldSelector = "metadata.name=" + name
		}

		lister, err := s.nsInterface.List(listOptions)
		return lister.Items, err
	}

	//-------------------------------------
	//	Find by labels
	//-------------------------------------

	byLabels := func(labels map[string]string) ([]core_v1.Namespace, error) {
		if labels == nil {
			return []core_v1.Namespace{}, errors.New("Namespace labels is nil")
		}

		lister, err := s.nsInterface.List(meta_v1.ListOptions{
			LabelSelector: implodeLabels(labels),
		})

		return lister.Items, err
	}

	//	Get the appropriate function
	switch strings.ToLower(query.By) {
	case "name":
		return byName(query.Name)
	case "labels":
		return byLabels(query.Labels)
	default:
		return []core_v1.Namespace{}, errors.New("Unrecognized namespace query")
	}
}
