//go:build amd64 && linux
// +build amd64,linux

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

package dynamicpolicy

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	libcontainercgroups "github.com/opencontainers/runc/libcontainer/cgroups"
	"golang.org/x/sys/unix"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/pkg/kubelet/cm/topologymanager/bitmask"

	"github.com/kubewharf/katalyst-core/pkg/metrics"
	"github.com/kubewharf/katalyst-core/pkg/util/asyncworker"
	"github.com/kubewharf/katalyst-core/pkg/util/cgroup/common"
	cgroupmgr "github.com/kubewharf/katalyst-core/pkg/util/cgroup/manager"
	"github.com/kubewharf/katalyst-core/pkg/util/general"
	"github.com/kubewharf/katalyst-core/pkg/util/machine"
)

// move_pages flags, MPOL_MF_MOVE means Move pages owned by this process to conform to policy
const MPOL_MF_MOVE = (1 << 1)

const (
	// get numa for 16384 pages(64MB) at most at a time, get numa for 65536 pages costs about 5ms
	GetNumaForPagesMaxEachTime = 16384
	// move 5120 pages(20MB) at most at a time
	MovePagesMaxEachTime = 5120
	// move 256 pages(1MB) at least at a time
	MovePagesMinEachTime = 256
	// acceptable time cost of each move pages is 20ms
	MovePagesAcceptableTimeCost = 20
	MBytes                      = 1024 * 1024
)

type vmaInfo struct {
	start       uint64
	end         uint64
	virtualSize int64
	rss         int64
	pageSize    int64
}

type smapsInfo struct {
	totalRss int64
	vmas     []vmaInfo
}

func MigratePagesForContainer(ctx context.Context, podUID, containerId string,
	numasCount int, sourceNUMAs, destNUMAs machine.CPUSet) error {
	memoryAbsCGPath, err := common.GetContainerAbsCgroupPath(common.CgroupSubsysMemory, podUID, containerId)
	if err != nil {
		return fmt.Errorf("GetContainerAbsCgroupPath failed with error: %v", err)
	}

	containerPids, err := cgroupmgr.GetPidsWithAbsolutePath(memoryAbsCGPath)
	if err != nil {
		return fmt.Errorf("GetPidsWithAbsolutePath: %s failed with error: %v", memoryAbsCGPath, err)
	}

	sourceMask, err := bitmask.NewBitMask(sourceNUMAs.ToSliceInt()...)
	if err != nil {
		return fmt.Errorf("convert sourceNUMAs: %s to mask failed with error: %v", sourceNUMAs.String(), err)
	}

	destMask, err := bitmask.NewBitMask(destNUMAs.ToSliceInt()...)
	if err != nil {
		return fmt.Errorf("convert destNUMAs: %s to mask failed with error: %v", destNUMAs.String(), err)
	}

	var errList []error
containerLoop:
	for _, containerPidStr := range containerPids {
		containerPid, err := strconv.Atoi(containerPidStr)
		if err != nil {
			errList = append(errList, fmt.Errorf("pod: %s, container: %s, pid: %s invalid ",
				podUID, containerId, containerPidStr))
		}

		_, _, errNo := unix.Syscall6(unix.SYS_MIGRATE_PAGES,
			uintptr(containerPid),
			uintptr(numasCount+1),
			uintptr(reflect.ValueOf(sourceMask).UnsafePointer()),
			uintptr(reflect.ValueOf(destMask).UnsafePointer()), 0, 0)
		if errNo != 0 {
			errList = append(errList, fmt.Errorf("pod: %s, container: %s, pid: %d, migrates pages from %s to %s failed with error: %v",
				podUID, containerId, containerPid, sourceNUMAs.String(), destNUMAs.String(), errNo.Error()))
		}

		select {
		case <-ctx.Done():
			break containerLoop
		default:
		}
	}

	err = utilerrors.NewAggregate(errList)
	_ = asyncworker.EmitAsyncedMetrics(ctx, metrics.ConvertMapToTags(map[string]string{
		"podUID":      podUID,
		"containerID": containerId,
		"succeeded":   fmt.Sprintf("%v", err == nil),
	})...)

	return err
}

func MovePagesForContainer(ctx context.Context, podUID, containerId string,
	sourceNUMAs, destNUMAs machine.CPUSet) error {
	memoryAbsCGPath, err := common.GetContainerAbsCgroupPath(common.CgroupSubsysMemory, podUID, containerId)
	if err != nil {
		return fmt.Errorf("GetContainerAbsCgroupPath failed with error: %v", err)
	}

	sourceNUMAs = sourceNUMAs.Difference(destNUMAs)
	if len(sourceNUMAs.ToSliceInt()) == 0 {
		return nil
	}

	containerPids, err := libcontainercgroups.GetAllPids(memoryAbsCGPath)
	if err != nil {
		return fmt.Errorf("failed to GetAllPids(%s), err %v", memoryAbsCGPath, err)
	}

	var errList []error
containerLoop:
	for _, pid := range containerPids {
		start := time.Now()
		if err := MovePagesForProcess(ctx, pid, sourceNUMAs.ToSliceInt(), destNUMAs.ToSliceInt()); err != nil {
			errList = append(errList, fmt.Errorf("pod: %s, container: %s, pid: %d invalid ",
				podUID, containerId, pid))
			general.Errorf("failed to MovePagesForProcess, cgroup: %s, pid: %d, source numas: %+v, dest numas: %+v, err %v\n",
				memoryAbsCGPath, pid, sourceNUMAs, destNUMAs, err)

			continue
		}

		timeCost := time.Since(start).Milliseconds()
		general.Infof("MovePagesForProcess, cgroup: %s, pid: %d, source numas: %+v, dest numas: %+v), timecost: %dms",
			memoryAbsCGPath, pid, sourceNUMAs, destNUMAs, timeCost)
		select {
		case <-ctx.Done():
			break containerLoop
		default:
		}
	}

	err = utilerrors.NewAggregate(errList)
	_ = asyncworker.EmitAsyncedMetrics(ctx, metrics.ConvertMapToTags(map[string]string{
		"podUID":      podUID,
		"containerID": containerId,
		"succeeded":   fmt.Sprintf("%v", err == nil),
	})...)

	return err
}

func MovePagesForProcess(ctx context.Context, pid int, srcNumas []int, dstNumas []int) error {
	smapsInfo, err := getProcessPageStats(pid)
	if err != nil {
		return err
	}

	// skip process whose rss less than 10MB
	if smapsInfo.totalRss < 10*MBytes {
		general.Infof("pid: %d, totalRss: %d", pid, smapsInfo.totalRss)
		return nil
	}

	srcNumasBitSet, err := bitmask.NewBitMask(srcNumas...)
	if err != nil {
		return fmt.Errorf("failed to NewBitMask allowd numas %+v", srcNumas)
	}

	var getPagesNumaLatencyMax int64

	pagesMargin := GetNumaForPagesMaxEachTime
	var pagesAdrr []uint64
	var phyPagesAddr []uint64

	getPhyPagesOnSourceNumas := func() {
		start := time.Now()
		pagesNuma, err := getProcessPagesNuma(int32(pid), uint64(len(pagesAdrr)), pagesAdrr)
		timeCost := time.Since(start).Milliseconds()
		if timeCost > getPagesNumaLatencyMax {
			getPagesNumaLatencyMax = timeCost
		}
		if err == nil {
			for i, n := range pagesNuma {
				if srcNumasBitSet.IsSet(int(n)) {
					pageAddr := pagesAdrr[i]
					phyPagesAddr = append(phyPagesAddr, pageAddr)
				}
			}
		} else {
			general.Errorf("failed to getProcessPagesNuma for pid:%d, err %v", pid, err)
		}
	}

	for _, vma := range smapsInfo.vmas {
		for addr := vma.start; addr < vma.end; addr += uint64(vma.pageSize) {
			pagesAdrr = append(pagesAdrr, addr)
			pagesMargin--
			if pagesMargin == 0 {
				getPhyPagesOnSourceNumas()
				pagesMargin = GetNumaForPagesMaxEachTime
				pagesAdrr = pagesAdrr[:0]
			}
		}
	}

	// handle left pagesAddr whose length less than GetNumaForPagesMaxEachTime
	if len(pagesAdrr) > 0 {
		getPhyPagesOnSourceNumas()
	}

	general.Infof("pid: %d, getPagesNumaLatencyMax: %dms", pid, getPagesNumaLatencyMax)

	if len(phyPagesAddr) == 0 {
		general.Infof("pid: %d has zero pages to be move", pid)
		return nil
	}

	// needless get getNumasFreeMemRatio after each move_pages,
	// only call getNumasFreeMemRatio here is enough.
	dstNumasFreeMemRatio, err := getNumasFreeMemRatio(dstNumas)
	if err != nil {
		return err
	}

	if len(dstNumasFreeMemRatio) == 0 {
		return fmt.Errorf("pid: %d dstNumasFreeMemRatio is zero", pid)
	}

	// DEBUG getNumasFreeMemRatio START
	general.Infof("dest numa free memory ratio:")
	for numaID, ratio := range dstNumasFreeMemRatio {
		general.Infof("  %d: %d", numaID, ratio)
	}
	// DEBUG getNumasFreeMemRatio END

	ratioTotal := 0
	for _, r := range dstNumasFreeMemRatio {
		ratioTotal += r
	}

	phyPagesAddrNext := 0
	var phyPagesToNuma []uint64
	totalPages := 0
	numaCount := 0

	var errList []error
numaLoop:
	for numaID, ratio := range dstNumasFreeMemRatio {
		pagesCount := len(phyPagesAddr) * ratio / ratioTotal
		totalPages += pagesCount
		if totalPages > len(phyPagesAddr) {
			return fmt.Errorf("impossible, totalPages:%d greater than phyPagesAddr length: %d", totalPages, len(phyPagesAddr))
		}

		numaCount++
		start := phyPagesAddrNext
		if numaCount == len(dstNumasFreeMemRatio) { // last dest numa
			phyPagesToNuma = phyPagesAddr[start:]
		} else {
			end := phyPagesAddrNext + pagesCount
			phyPagesAddrNext = end
			phyPagesToNuma = phyPagesAddr[start:end]
		}

		if err := moveProcessPagesToOneNuma(ctx, int32(pid), phyPagesToNuma, numaID); err != nil {
			general.Errorf("failed to moveProcessPagesToOneNuma, err: %v", err)
			errList = append(errList, err)
			continue
		}

		select {
		case <-ctx.Done():
			break numaLoop
		default:
		}
	}

	return utilerrors.NewAggregate(errList)
}

func moveProcessPagesToOneNuma(ctx context.Context, pid int32, pagesAddr []uint64, dstNuma int) (err error) {
	leftPhyPages := pagesAddr[:]

	var movePagesLatencyMax int64

	movePagesEachTime := MovePagesMinEachTime
	var movingPagesAddr []uint64

	var errList []error
pagesLoop:
	for len(leftPhyPages) > 0 {
		if len(leftPhyPages) > movePagesEachTime {
			movingPagesAddr = leftPhyPages[:movePagesEachTime]
			leftPhyPages = leftPhyPages[movePagesEachTime:]
		} else {
			movingPagesAddr = leftPhyPages[:]
			leftPhyPages = leftPhyPages[:0]
		}

		nodes := make([]int32, len(movingPagesAddr))
		for i := range movingPagesAddr {
			nodes[i] = int32(dstNuma)
		}

		start := time.Now()
		_, err := moveProcessPages(pid, uint64(len(movingPagesAddr)), movingPagesAddr, nodes)
		if err != nil {
			general.Errorf("failed to moveProcessPages for pid: %d, err: %v", pid, err)
			errList = append(errList, fmt.Errorf("failed move pages for pid: %d, numa: %d err: %v", pid, dstNuma, err))
			continue
		}
		timeCost := time.Since(start).Milliseconds()
		if timeCost > movePagesLatencyMax {
			movePagesLatencyMax = timeCost
		}

		if timeCost == 0 {
			movePagesEachTime = MovePagesMaxEachTime
			continue
		}

		movePagesEachTime = movePagesEachTime * MovePagesAcceptableTimeCost / int(timeCost)
		if movePagesEachTime < MovePagesMinEachTime {
			movePagesEachTime = MovePagesMinEachTime
		} else if movePagesEachTime > MovePagesMaxEachTime {
			movePagesEachTime = MovePagesMaxEachTime
		}

		select {
		case <-ctx.Done():
			break pagesLoop
		default:
		}
	}

	general.Infof("pid: %d, numa: %d, movePagesLatencyMax: %dms", pid, dstNuma, movePagesLatencyMax)

	return utilerrors.NewAggregate(errList)
}

func getNumaNodeFreeMemMB(nodeID int) (uint64, error) {
	nodeVmstatFile := fmt.Sprintf("/sys/devices/system/node/node%d/vmstat", nodeID)
	lines, err := general.ReadFileIntoLines(nodeVmstatFile)
	if err != nil {
		e := fmt.Errorf("failed to ReadFile %s, err %s", nodeVmstatFile, err)
		return 0, e
	}

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid line %s in vmstat file %s", line, nodeVmstatFile)
		}

		if fields[0] != "nr_free_pages" {
			continue
		}

		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid line %s in vmstat file %s, err %s", line, nodeVmstatFile, err)
		}

		return val * 4 / 1024, nil
	}

	return 0, fmt.Errorf("failed to find nr_free_pages in %s", nodeVmstatFile)
}

// ratio range [1, 10], so return value is an approximate value
func getNumasFreeMemRatio(numas []int) (map[int]int, error) {
	var totalSize uint64
	numaFreeMem := make(map[int]uint64)
	for _, n := range numas {
		freeMemSize, err := getNumaNodeFreeMemMB(n)
		if err != nil {
			return nil, fmt.Errorf("failed to getNumaNodeFreeMem for node %d, err %s", n, err)
		}

		numaFreeMem[n] = freeMemSize
		totalSize += freeMemSize
	}

	// convert numa free memory ratio to a approximate value which is in the range [1, 10]
	var fraction uint64 = 1
	if totalSize > 10 {
		fraction = (totalSize + 10) / 10
	}

	numaFreeMemRatio := make(map[int]int)
	for numaID, freeMemSize := range numaFreeMem {
		val := freeMemSize / fraction
		if val == 0 {
			continue
		}
		numaFreeMemRatio[numaID] = int(val)
	}

	return numaFreeMemRatio, nil
}

func getProcessPageStats(pid int) (*smapsInfo, error) {
	smapFile := fmt.Sprintf("/proc/%d/smaps", pid)
	lines, err := general.ReadFileIntoLines(smapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to ReadLines(%s), err %v", smapFile, err)
	}

	info := &smapsInfo{}
	var vma *vmaInfo
	for _, line := range lines {
		if vma == nil {
			elems := strings.Fields(line)
			if len(elems) == 0 {
				general.Errorf("invalid empty vma first line: %s", line)
				continue
			}

			vmaRange := strings.Split(elems[0], "-")
			if len(vmaRange) != 2 {
				general.Errorf("invalid vma first line: %s", line)
				continue
			}

			vmaStart, err := strconv.ParseUint(vmaRange[0], 16, 64)
			if err != nil {
				general.Errorf("invalid vma first line: %s, failed to ParseUint vma start %s, err %v", line, vmaRange[0], err)
				continue
			}

			vmaEnd, err := strconv.ParseUint(vmaRange[1], 16, 64)
			if err != nil {
				general.Errorf("invalid vma first line: %s, failed to ParseUint vma end %s, err %v", line, vmaRange[1], err)
				continue
			}

			vma = &vmaInfo{
				start:       vmaStart,
				end:         vmaEnd,
				virtualSize: -1,
				rss:         -1,
				pageSize:    -1,
			}
			continue
		}

		if strings.HasPrefix(line, "Size:") {
			elems := strings.Fields(line)
			if len(elems) != 3 {
				general.Errorf("invalid vma Size line: %s", line)
				continue
			}

			sizeKB, err := strconv.ParseInt(elems[1], 10, 64)
			if err != nil {
				general.Errorf("invalid vma line: %s, failed to ParseInt Size %s, err %v", line, elems[1], err)
				continue
			}
			vma.virtualSize = sizeKB * 1024
			continue
		}

		if strings.HasPrefix(line, "KernelPageSize:") {
			elems := strings.Fields(line)
			if len(elems) != 3 {
				general.Errorf("invalid vma KernelPageSize line: %s", line)
				continue
			}

			pageSizeKB, err := strconv.ParseInt(elems[1], 10, 64)
			if err != nil {
				general.Errorf("invalid vma line: %s, failed to ParseInt KernelPageSize %s, err %v", line, elems[1], err)
				continue
			}
			vma.pageSize = pageSizeKB * 1024
			continue
		}

		if strings.HasPrefix(line, "Rss:") {
			elems := strings.Fields(line)
			if len(elems) != 3 {
				general.Errorf("invalid vma Rss line: %s", line)
				continue
			}

			rssKB, err := strconv.ParseInt(elems[1], 10, 64)
			if err != nil {
				general.Errorf("invalid vma line: %s, failed to ParseInt Rss %s, err %v", line, elems[1], err)
				continue
			}
			vma.rss = rssKB * 1024
			continue
		}

		if strings.HasPrefix(line, "VmFlags:") {
			if vma.virtualSize == -1 {
				general.Errorf("invalid vma(%x-%x), without Size line", vma.start, vma.end)
				continue
			}
			if vma.rss == -1 {
				general.Errorf("invalid vma(%x-%x), without Rss line", vma.start, vma.end)
				continue
			}
			if vma.pageSize == -1 {
				general.Errorf("invalid vma(%x-%x), without KernelPageSize line", vma.start, vma.end)
				continue
			}

			info.totalRss += vma.rss
			info.vmas = append(info.vmas, *vma)
			vma = nil
		}
	}

	return info, nil
}

func getProcessPagesNuma(pid int32, pagesCount uint64, pagesAddr []uint64) (pagesNuma []int32, err error) {
	return movePages(pid, pagesCount, pagesAddr, nil)
}

func moveProcessPages(pid int32, pagesCount uint64, pagesAddr []uint64, nodes []int32) (pagesNuma []int32, err error) {
	return movePages(pid, pagesCount, pagesAddr, nodes)
}

func movePages(pid int32, pagesCount uint64, pagesAddr []uint64, nodes []int32) (pagesNuma []int32, err error) {
	status := make([]int32, pagesCount)
	for i := range status {
		status[i] = -111
	}

	var nodesBaseAddr *int32
	if len(nodes) > 0 {
		nodesBaseAddr = &nodes[0]
	}

	moveFlags := int32(MPOL_MF_MOVE)
	_, _, errNo := unix.Syscall6(unix.SYS_MOVE_PAGES,
		uintptr(pid),
		uintptr(pagesCount),
		uintptr(unsafe.Pointer(&pagesAddr[0])),
		uintptr(unsafe.Pointer(nodesBaseAddr)),
		uintptr(unsafe.Pointer(&status[0])),
		uintptr(moveFlags))

	if errNo != 0 {
		return nil, fmt.Errorf("failed to call SYS_MOVE_PAGES syscall, err %v", errNo.Error())
	}

	return status, nil
}
