/*
Copyright 2022 The Katalyst Authors.

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

package region

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/pointer"

	"github.com/kubewharf/katalyst-api/pkg/apis/config/v1alpha1"
	configapi "github.com/kubewharf/katalyst-api/pkg/apis/config/v1alpha1"
	"github.com/kubewharf/katalyst-api/pkg/consts"
	katalyst_base "github.com/kubewharf/katalyst-core/cmd/base"
	"github.com/kubewharf/katalyst-core/cmd/katalyst-agent/app/options"
	"github.com/kubewharf/katalyst-core/pkg/agent/qrm-plugins/cpu/dynamicpolicy/state"
	"github.com/kubewharf/katalyst-core/pkg/agent/sysadvisor/metacache"
	"github.com/kubewharf/katalyst-core/pkg/agent/sysadvisor/types"
	"github.com/kubewharf/katalyst-core/pkg/metaserver"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/agent/metric"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
	metricspool "github.com/kubewharf/katalyst-core/pkg/metrics/metrics-pool"
	"github.com/kubewharf/katalyst-core/pkg/util/machine"
)

func TestGetRegionNameFromMetaCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		container  *types.ContainerInfo
		numaID     int
		region     *types.RegionInfo
		regionName string
	}{
		{
			name: "shared-region",
			container: &types.ContainerInfo{
				QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
				RegionNames: sets.NewString("share-t"),
			},
			region: &types.RegionInfo{
				RegionName: "share-t",
				RegionType: configapi.QoSRegionTypeShare,
			},
			regionName: "share-t",
		},
		{
			name: "dedicated-region",
			container: &types.ContainerInfo{
				QoSLevel: consts.PodAnnotationQoSLevelDedicatedCores,
				Annotations: map[string]string{
					consts.PodAnnotationMemoryEnhancementNumaBinding: consts.PodAnnotationMemoryEnhancementNumaBindingEnable,
				},
				RegionNames: sets.NewString("dedicated-t"),
			},
			region: &types.RegionInfo{
				RegionName:   "dedicated-t",
				RegionType:   configapi.QoSRegionTypeDedicatedNumaExclusive,
				BindingNumas: machine.NewCPUSet(1),
			},
			numaID:     1,
			regionName: "dedicated-t",
		},
		{
			name: "dedicated-region-numa-miss",
			container: &types.ContainerInfo{
				QoSLevel: consts.PodAnnotationQoSLevelDedicatedCores,
				Annotations: map[string]string{
					consts.PodAnnotationMemoryEnhancementNumaBinding: consts.PodAnnotationMemoryEnhancementNumaBindingEnable,
				},
				RegionNames: sets.NewString("dedicated-t"),
			},
			region: &types.RegionInfo{
				RegionName:   "dedicated-t",
				RegionType:   configapi.QoSRegionTypeDedicatedNumaExclusive,
				BindingNumas: machine.NewCPUSet(1),
			},
			numaID:     2,
			regionName: "",
		},
		{
			name: "isolation-region",
			container: &types.ContainerInfo{
				QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
				RegionNames: sets.NewString("isolation-t"),
				Isolated:    true,
			},
			region: &types.RegionInfo{
				RegionName: "isolation-t",
				RegionType: configapi.QoSRegionTypeIsolation,
			},
			regionName: "isolation-t",
		},
		{
			name: "isolation-region-empty",
			container: &types.ContainerInfo{
				QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
				RegionNames: sets.NewString("isolation-t"),
				Isolated:    true,
			},
			region: &types.RegionInfo{
				RegionName: "isolation-t",
				RegionType: configapi.QoSRegionTypeShare,
			},
			regionName: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conf, err := options.NewOptions().Config()
			assert.NoError(t, err)
			conf.GenericSysAdvisorConfiguration.StateFileDirectory = os.TempDir()
			cache, err := metacache.NewMetaCacheImp(conf, metricspool.DummyMetricsEmitterPool{}, nil)
			assert.NoError(t, err)
			err = cache.SetRegionInfo(tt.region.RegionName, tt.region)
			assert.NoError(t, err)
			err = cache.SetContainerInfo(tt.container.PodUID, tt.container.ContainerName, tt.container)
			assert.NoError(t, err)

			assert.Equal(t, tt.regionName, getRegionNameFromMetaCache(tt.container, tt.numaID, cache))
		})
	}
}

func TestIsNumaBinding(t *testing.T) {
	t.Parallel()

	conf, err := options.NewOptions().Config()
	require.NoError(t, err)
	require.NotNil(t, conf)

	stateFileDir := "stateFileDir"
	checkpointDir := "checkpointDir"

	conf.GenericSysAdvisorConfiguration.StateFileDirectory = stateFileDir
	conf.MetaServerConfiguration.CheckpointManagerDir = checkpointDir
	conf.CPUShareConfiguration.RestrictRefPolicy = nil

	genericCtx, err := katalyst_base.GenerateFakeGenericContext([]runtime.Object{})
	require.NoError(t, err)

	metaServer, err := metaserver.NewMetaServer(genericCtx.Client, metrics.DummyMetrics{}, conf)
	require.NoError(t, err)
	defer func() {
		os.RemoveAll(stateFileDir)
		os.RemoveAll(checkpointDir)
	}()

	metaCache, err := metacache.NewMetaCacheImp(conf, metricspool.DummyMetricsEmitterPool{}, metric.NewFakeMetricsFetcher(metrics.DummyMetrics{}))
	require.NoError(t, err)
	ci := types.ContainerInfo{
		QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
		RegionNames: sets.NewString("share-NUMA1"),
	}
	share := NewQoSRegionShare(&ci, conf, nil, 1, metaCache, metaServer, metrics.DummyMetrics{})
	require.True(t, share.IsNumaBinding(), "test IsNumaBinding failed")

	ci2 := types.ContainerInfo{
		QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
		RegionNames: sets.NewString("share"),
	}
	share2 := NewQoSRegionShare(&ci2, conf, nil, state.FakedNUMAID, metaCache, metaServer, metrics.DummyMetrics{})
	require.False(t, share2.IsNumaBinding(), "test IsNumaBinding failed")

	ci3 := types.ContainerInfo{
		QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
		RegionNames: sets.NewString("isolation-NUMA1-1"),
		Isolated:    true,
	}
	isolation1 := NewQoSRegionIsolation(&ci3, "isolation-1", conf, nil, 1, metaCache, metaServer, metrics.DummyMetrics{})
	require.True(t, isolation1.IsNumaBinding(), "test IsNumaBinding failed")

	ci4 := types.ContainerInfo{
		QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
		RegionNames: sets.NewString("isolation-1"),
		Isolated:    true,
	}
	isolation2 := NewQoSRegionIsolation(&ci4, "isolation-1", conf, nil, state.FakedNUMAID, metaCache, metaServer, metrics.DummyMetrics{})
	require.False(t, isolation2.IsNumaBinding(), "test IsNumaBinding failed")
}

func TestRestrictProvisionControlKnob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		controlKnobConstraints map[v1alpha1.ControlKnobName]v1alpha1.RestrictConstraints
		originControlKnob      map[types.CPUProvisionPolicyName]types.ControlKnob
		wantControlKnob        map[types.CPUProvisionPolicyName]types.ControlKnob
	}{
		{
			name: "below ref",
			controlKnobConstraints: map[configapi.ControlKnobName]configapi.RestrictConstraints{
				"c1": {
					MaxUpperGap: pointer.Float64(4),
					MaxLowerGap: pointer.Float64(1),
				},
			},
			originControlKnob: map[types.CPUProvisionPolicyName]types.ControlKnob{"p1": {"c1": types.ControlKnobValue{Value: 8}}, "p2": {"c1": types.ControlKnobValue{Value: 10}}},
			wantControlKnob:   map[types.CPUProvisionPolicyName]types.ControlKnob{"p1": {"c1": types.ControlKnobValue{Value: 9}}, "p2": {"c1": types.ControlKnobValue{Value: 10}}},
		},
		{
			name: "upper ref",
			controlKnobConstraints: map[configapi.ControlKnobName]configapi.RestrictConstraints{
				"c1": {
					MaxUpperGap: pointer.Float64(4),
					MaxLowerGap: pointer.Float64(1),
				},
			},
			originControlKnob: map[types.CPUProvisionPolicyName]types.ControlKnob{"p1": {"c1": types.ControlKnobValue{Value: 16}}, "p2": {"c1": types.ControlKnobValue{Value: 10}}},
			wantControlKnob:   map[types.CPUProvisionPolicyName]types.ControlKnob{"p1": {"c1": types.ControlKnobValue{Value: 14}}, "p2": {"c1": types.ControlKnobValue{Value: 10}}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conf, err := options.NewOptions().Config()
			require.NoError(t, err)
			require.NotNil(t, conf)

			stateFileDir := "stateFileDir" + uuid.New().String()
			checkpointDir := "checkpointDir" + uuid.New().String()

			conf.GenericSysAdvisorConfiguration.StateFileDirectory = stateFileDir
			conf.MetaServerConfiguration.CheckpointManagerDir = checkpointDir
			conf.CPUShareConfiguration.RestrictRefPolicy = map[types.CPUProvisionPolicyName]types.CPUProvisionPolicyName{"p1": "p2"}
			conf.GetDynamicConfiguration().RestrictConstraints = tt.controlKnobConstraints

			genericCtx, err := katalyst_base.GenerateFakeGenericContext([]runtime.Object{})
			require.NoError(t, err)

			metaServer, err := metaserver.NewMetaServer(genericCtx.Client, metrics.DummyMetrics{}, conf)
			require.NoError(t, err)
			defer func() {
				os.RemoveAll(stateFileDir)
				os.RemoveAll(checkpointDir)
			}()

			metaCache, err := metacache.NewMetaCacheImp(conf, metricspool.DummyMetricsEmitterPool{}, metric.NewFakeMetricsFetcher(metrics.DummyMetrics{}))
			require.NoError(t, err)
			ci := types.ContainerInfo{
				QoSLevel:    consts.PodAnnotationQoSLevelSharedCores,
				RegionNames: sets.NewString("share"),
			}
			share := NewQoSRegionShare(&ci, conf, nil, state.FakedNUMAID, metaCache, metaServer, metrics.DummyMetrics{})
			restrictedControlKnobs := share.(*QoSRegionShare).restrictProvisionControlKnob(tt.originControlKnob)
			assert.Equal(t, tt.wantControlKnob, restrictedControlKnobs)
		})
	}
}
