// Copyright 2022 The Katalyst Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicpolicy

import (
	"context"
	"fmt"
	"github.com/kubewharf/katalyst-core/pkg/util/native"
	"github.com/kubewharf/katalyst-core/pkg/util/qos"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	pluginapi "k8s.io/kubelet/pkg/apis/resourceplugin/v1alpha1"

	apiconsts "github.com/kubewharf/katalyst-api/pkg/consts"
	"github.com/kubewharf/katalyst-api/pkg/plugins/skeleton"
	"github.com/kubewharf/katalyst-core/cmd/katalyst-agent/app/agent"
	"github.com/kubewharf/katalyst-core/pkg/agent/qrm-plugins/util"
	"github.com/kubewharf/katalyst-core/pkg/config"
	"github.com/kubewharf/katalyst-core/pkg/config/generic"
	"github.com/kubewharf/katalyst-core/pkg/metaserver"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
	"github.com/kubewharf/katalyst-core/pkg/util/cgroup/common"
	cgroupcmutils "github.com/kubewharf/katalyst-core/pkg/util/cgroup/manager"
	"github.com/kubewharf/katalyst-core/pkg/util/general"
)

const (
	// NetworkResourcePluginPolicyNameDynamic is the policy name of dynamic network resource plugin
	NetworkResourcePluginPolicyNameDynamic = "dynamic"
	// ResourceNameNetwork is the resource name of network
	ResourceNameNetwork = "network"
)

// DynamicPolicy is the dynamic network policy
type DynamicPolicy struct {
	sync.RWMutex

	name       string
	stopCh     chan struct{}
	started    bool
	qosConfig  *generic.QoSConfiguration
	emitter    metrics.MetricEmitter
	metaServer *metaserver.MetaServer

	netClassMap                   map[string]uint32
	isCgV2Env                     bool
	applyNetClassFunc             func(podUID, containerId string, data *common.NetClsData) error
	podLevelNetClassAnnoKey       string
	podLevelNetAttributesAnnoKeys []string
}

// NewDynamicPolicy returns a dynamic network policy
func NewDynamicPolicy(agentCtx *agent.GenericContext, conf *config.Configuration, _ interface{}, agentName string) (bool, agent.Component, error) {
	wrappedEmitter := agentCtx.EmitterPool.GetDefaultMetricsEmitter().WithTags(agentName, metrics.MetricTag{
		Key: util.QRMPluginPolicyTagName,
		Val: NetworkResourcePluginPolicyNameDynamic,
	})

	policyImplement := &DynamicPolicy{
		qosConfig:   conf.QoSConfiguration,
		emitter:     wrappedEmitter,
		metaServer:  agentCtx.MetaServer,
		stopCh:      make(chan struct{}),
		name:        fmt.Sprintf("%s_%s", agentName, NetworkResourcePluginPolicyNameDynamic),
		netClassMap: make(map[string]uint32),
	}

	if common.IsCgroup2UnifiedMode() {
		policyImplement.isCgV2Env = true
		policyImplement.applyNetClassFunc = agentCtx.MetaServer.ExternalManager.ApplyNetClass
	} else {
		policyImplement.isCgV2Env = false
		policyImplement.applyNetClassFunc = cgroupcmutils.ApplyNetClsForContainer
	}

	policyImplement.ApplyConfig(conf.DynamicConfiguration)

	pluginWrapper, err := skeleton.NewRegistrationPluginWrapper(
		policyImplement,
		conf.QRMPluginSocketDirs, nil)
	if err != nil {
		return false, agent.ComponentStub{}, fmt.Errorf("dynamic policy new plugin wrapper failed with error: %v", err)
	}

	return true, &agent.PluginWrapper{GenericPlugin: pluginWrapper}, nil
}

// ApplyConfig applies config to DynamicPolicy
func (p *DynamicPolicy) ApplyConfig(conf *config.DynamicConfiguration) {
	p.Lock()
	defer p.Unlock()

	p.netClassMap[apiconsts.PodAnnotationQoSLevelReclaimedCores] = conf.NetClass.ReclaimedCores
	p.netClassMap[apiconsts.PodAnnotationQoSLevelSharedCores] = conf.NetClass.SharedCores
	p.netClassMap[apiconsts.PodAnnotationQoSLevelDedicatedCores] = conf.NetClass.DedicatedCores
	p.netClassMap[apiconsts.PodAnnotationQoSLevelSystemCores] = conf.NetClass.SystemCores

	p.podLevelNetClassAnnoKey = conf.PodLevelNetClassAnnoKey
	p.podLevelNetAttributesAnnoKeys = strings.Split(conf.PodLevelNetAttributesAnnoKeys, ",")

	klog.Infof("[network-resource-plugin] apply configs, "+
		"netClassMap: %+v, "+
		"podLevelNetClassAnnoKey: %s, "+
		"podLevelNetAttributesAnnoKeys: %+v",
		p.netClassMap,
		p.podLevelNetClassAnnoKey,
		p.podLevelNetAttributesAnnoKeys)
}

// Start starts this plugin
func (p *DynamicPolicy) Start() (err error) {
	klog.Infof("MemoryDynamicPolicy start called")

	p.Lock()

	defer func() {
		if err == nil {
			p.started = true
		}

		p.Unlock()
	}()

	if p.started {
		klog.Infof("[NetworkDynamicPolicy.Start] DynamicPolicy is already started")
		return nil
	}

	p.stopCh = make(chan struct{})

	go wait.Until(func() {
		_ = p.emitter.StoreInt64(util.MetricNameHeartBeat, 1, metrics.MetricTypeNameRaw)
	}, time.Second*30, p.stopCh)

	go wait.Until(p.applyNetClass, 5*time.Second, p.stopCh)

	return nil
}

// Stop stops this plugin
func (p *DynamicPolicy) Stop() error {
	p.Lock()
	defer func() {
		p.started = false
		p.Unlock()

		klog.Infof("[NetworkDynamicPolicy.Stop] DynamicPolicy stopped")
	}()

	if !p.started {
		klog.Warningf("[NetworkDynamicPolicy.Stop] DynamicPolicy already stopped")
		return nil
	}
	close(p.stopCh)
	return nil
}

// Name returns the name of this plugin
func (p *DynamicPolicy) Name() string {
	return p.name
}

// ResourceName returns resource names managed by this plugin
func (p *DynamicPolicy) ResourceName() string {
	return ResourceNameNetwork
}

// GetTopologyHints returns hints of corresponding resources
func (p *DynamicPolicy) GetTopologyHints(ctx context.Context, req *pluginapi.ResourceRequest) (*pluginapi.ResourceHintsResponse, error) {
	return nil, nil
}

func (p *DynamicPolicy) RemovePod(ctx context.Context, req *pluginapi.RemovePodRequest) (*pluginapi.RemovePodResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RemovePod got nil req")
	}

	if p.isCgV2Env {
		err := p.removePod(req.PodUid)
		if err != nil {
			klog.ErrorS(err, "[NetworkDynamicPolicy.RemovePod] remove pod failed with error", "podUID", req.PodUid)
			return nil, err
		}
	}

	return &pluginapi.RemovePodResponse{}, nil
}

// GetResourcesAllocation returns allocation results of corresponding resources
func (p *DynamicPolicy) GetResourcesAllocation(ctx context.Context, req *pluginapi.GetResourcesAllocationRequest) (*pluginapi.GetResourcesAllocationResponse, error) {
	return nil, nil
}

// GetTopologyAwareResources returns allocation results of corresponding resources as topology aware format
func (p *DynamicPolicy) GetTopologyAwareResources(ctx context.Context, req *pluginapi.GetTopologyAwareResourcesRequest) (*pluginapi.GetTopologyAwareResourcesResponse, error) {
	return nil, nil
}

// GetTopologyAwareAllocatableResources returns corresponding allocatable resources as topology aware format
func (p *DynamicPolicy) GetTopologyAwareAllocatableResources(ctx context.Context, req *pluginapi.GetTopologyAwareAllocatableResourcesRequest) (*pluginapi.GetTopologyAwareAllocatableResourcesResponse, error) {
	return nil, nil
}

// GetResourcePluginOptions returns options to be communicated with Resource Manager
func (p *DynamicPolicy) GetResourcePluginOptions(context.Context, *pluginapi.Empty) (*pluginapi.ResourcePluginOptions, error) {
	return &pluginapi.ResourcePluginOptions{
		PreStartRequired:      false,
		WithTopologyAlignment: false,
		NeedReconcile:         false,
	}, nil
}

// Allocate is called during pod admit so that the resource
// plugin can allocate corresponding resource for the container
// according to resource request
func (p *DynamicPolicy) Allocate(ctx context.Context, req *pluginapi.ResourceRequest) (resp *pluginapi.ResourceAllocationResponse, respErr error) {
	return &pluginapi.ResourceAllocationResponse{
		PodUid:         req.PodUid,
		PodNamespace:   req.PodNamespace,
		PodName:        req.PodName,
		ContainerName:  req.ContainerName,
		ContainerType:  req.ContainerType,
		ContainerIndex: req.ContainerIndex,
		PodRole:        req.PodRole,
		PodType:        req.PodType,
		ResourceName:   ResourceNameNetwork,
		AllocationResult: &pluginapi.ResourceAllocation{
			ResourceAllocation: map[string]*pluginapi.ResourceAllocationInfo{
				ResourceNameNetwork: {},
			},
		},
		Labels:      general.DeepCopyMap(req.Labels),
		Annotations: general.DeepCopyMap(req.Annotations),
	}, nil
}

// PreStartContainer is called, if indicated by resource plugin during registeration phase,
// before each container start. Resource plugin can run resource specific operations
// such as resetting the resource before making resources available to the container
func (p *DynamicPolicy) PreStartContainer(context.Context, *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return nil, nil
}

func (p *DynamicPolicy) applyNetClass() {

}

func (p *DynamicPolicy) removePod(podUID string) error {


	return nil
}


