/*
 * Copyright (c) 2004-2009 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
 * Copyright (c) 2009-2010 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#include "TargetConditionals.h"

#include <sys/param.h>
#include <sys/mount.h>
#if !TARGET_OS_IPHONE
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#if defined(__aarch64__)
struct nfsstats {
 	uint64_t        attrcache_hits;
 	uint64_t        attrcache_misses;
 	uint64_t        lookupcache_hits;
 	uint64_t        lookupcache_misses;
 	uint64_t        direofcache_hits;
 	uint64_t        direofcache_misses;
 	uint64_t        biocache_reads;
 	uint64_t        read_bios;
 	uint64_t        read_physios;
 	uint64_t        biocache_writes;
 	uint64_t        write_bios;
 	uint64_t        write_physios;
 	uint64_t        biocache_readlinks;
 	uint64_t        readlink_bios;
 	uint64_t        biocache_readdirs;
 	uint64_t        readdir_bios;
 	uint64_t        rpccnt[NFS_NPROCS];
 	uint64_t        rpcretries;
 	uint64_t        srvrpccnt[NFS_NPROCS];
 	uint64_t        srvrpc_errs;
 	uint64_t        srv_errs;
 	uint64_t        rpcrequests;
 	uint64_t        rpctimeouts;
 	uint64_t        rpcunexpected;
 	uint64_t        rpcinvalid;
 	uint64_t        srvcache_inproghits;
 	uint64_t        srvcache_idemdonehits;
 	uint64_t        srvcache_nonidemdonehits;
 	uint64_t        srvcache_misses;
 	uint64_t        srvvop_writes;
 	uint64_t        pageins;
 	uint64_t        pageouts;
};
#endif
#endif

#include <dlfcn.h>
#include <mach/mach_init.h>
#include <mach/message.h>
#include <mach/kern_return.h>
#include <mach/mach_host.h>
#include <mach/mach_traps.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#if !TARGET_OS_IPHONE
#if !defined(HAVE_SHARED_REGION_H) && defined(__MAC_10_5) /* see Availability.h */
#  define HAVE_SHARED_REGION_H /* suckit autoconf */
#endif
#ifdef HAVE_SHARED_REGION_H
#include <mach/shared_region.h> /* does not exist in 10.4 SDK */
#else
#include <mach/shared_memory_server.h> /* deprecated in Leopard */
#endif
#endif
#include <mach-o/dyld.h>
#define __OPENTRANSPORTPROVIDERS__
#if !TARGET_OS_IPHONE
#include <CoreServices/CoreServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOTypes.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#endif

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>

#if TARGET_OS_IPHONE
#include "if_types.h"
#include "tcp_fsm.h"
#define RTM_NEWADDR 0xc /* address being added to iface */
#define RTM_IFINFO  0xe /* iface going up/down etc. */
#else
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <dirent.h>
#include <errno.h>

#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#if !TARGET_OS_IPHONE
#include <netinet/tcp_fsm.h>
#endif

#include <sys/utsname.h>

#define NMIB(mib) (sizeof(mib)/sizeof(mib[0]))

#define KI_FD   kp_proc.p_fd
#define KI_PID  kp_proc.p_pid
#define KI_PPID kp_eproc.e_ppid
#define KI_PRI  kp_proc.p_priority
#define KI_NICE kp_proc.p_nice
#define KI_COMM kp_proc.p_comm
#define KI_STAT kp_proc.p_stat
#define KI_UID  kp_eproc.e_pcred.p_ruid
#define KI_GID  kp_eproc.e_pcred.p_rgid
#define KI_EUID kp_eproc.e_pcred.p_svuid
#define KI_EGID kp_eproc.e_pcred.p_svgid
#define KI_SIZE XXX
#define KI_RSS  kp_eproc.e_vm.vm_rssize
#define KI_TSZ  kp_eproc.e_vm.vm_tsize
#define KI_DSZ  kp_eproc.e_vm.vm_dsize
#define KI_SSZ  kp_eproc.e_vm.vm_ssize
#define KI_FLAG kp_eproc.e_flag
#define KI_START kp_proc.p_starttime

int sigar_sys_info_get_uuid(sigar_t *sigar, char uuid[SIGAR_SYS_INFO_LEN])
{
    return SIGAR_ENOTIMPL;
}

int sigar_os_open(sigar_t **sigar)
{
    int mib[2];
    int ncpu;
    size_t len;
    struct timeval boottime;

    len = sizeof(ncpu);
    mib[0] = CTL_HW;
    mib[1] = HW_NCPU;
    if (sysctl(mib, NMIB(mib), &ncpu,  &len, NULL, 0) < 0) {
        return errno;
    }

    len = sizeof(boottime);
    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    if (sysctl(mib, NMIB(mib), &boottime, &len, NULL, 0) < 0) {
        return errno;
    }

    *sigar = malloc(sizeof(**sigar));

    (*sigar)->mach_port = mach_host_self();
#  ifdef DARWIN_HAS_LIBPROC_H
    if (((*sigar)->libproc = dlopen("/usr/lib/libproc.dylib", 0))) {
        (*sigar)->proc_pidinfo = dlsym((*sigar)->libproc, "proc_pidinfo");
        (*sigar)->proc_pidfdinfo = dlsym((*sigar)->libproc, "proc_pidfdinfo");
    }
#  endif

    (*sigar)->ncpu = ncpu;
    (*sigar)->lcpu = -1;
    (*sigar)->argmax = 0;
    (*sigar)->boot_time = boottime.tv_sec; /* XXX seems off a bit */

    (*sigar)->pagesize = getpagesize();
    (*sigar)->ticks = sysconf(_SC_CLK_TCK);
    (*sigar)->last_pid = -1;

    (*sigar)->pinfo = NULL;

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    if (sigar->pinfo) {
        free(sigar->pinfo);
    }
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    switch (err) {
      case SIGAR_EPERM_KMEM:
        return "Failed to open /dev/kmem for reading";
      case SIGAR_EPROC_NOENT:
        return "/proc filesystem is not mounted";
      default:
        return NULL;
    }
}

/* ARG_MAX in FreeBSD 6.0 == 262144, which blows up the stack */
#define SIGAR_ARG_MAX 65536

static size_t sigar_argmax_get(sigar_t *sigar)
{
#ifdef KERN_ARGMAX
    int mib[] = { CTL_KERN, KERN_ARGMAX };
    size_t size = sizeof(sigar->argmax);

    if (sigar->argmax != 0) {
        return sigar->argmax;
    }
    if (sysctl(mib, NMIB(mib), &sigar->argmax, &size, NULL, 0) == 0) {
        return sigar->argmax;
    }
#endif
    return SIGAR_ARG_MAX;
}

static int sigar_vmstat(sigar_t *sigar, vm_statistics_data_t *vmstat)
{
    kern_return_t status;
    mach_msg_type_number_t count = sizeof(*vmstat) / sizeof(integer_t);

    status = host_statistics(sigar->mach_port, HOST_VM_INFO,
                             (host_info_t)vmstat, &count);

    if (status == KERN_SUCCESS) {
        return SIGAR_OK;
    }
    else {
        return errno;
    }
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_uint64_t kern = 0;
    vm_statistics_data_t vmstat;
    uint64_t mem_total;
    int mib[2];
    size_t len;
    int status;

    mib[0] = CTL_HW;

    mib[1] = HW_PAGESIZE;
    len = sizeof(sigar->pagesize);
    if (sysctl(mib, NMIB(mib), &sigar->pagesize, &len, NULL, 0) < 0) {
        return errno;
    }

    mib[1] = HW_MEMSIZE;
    len = sizeof(mem_total);
    if (sysctl(mib, NMIB(mib), &mem_total, &len, NULL, 0) < 0) {
        return errno;
    }

    mem->total = mem_total;

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }

    mem->free = vmstat.free_count;
    mem->free *= sigar->pagesize;
    kern = vmstat.inactive_count;
    kern *= sigar->pagesize;

    mem->used = mem->total - mem->free;

    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

#define SWI_MAXMIB 3

#define getswapinfo_sysctl(swap_ary, swap_max) SIGAR_ENOTIMPL

#define SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) ((val * bsize) >> 1)

#define VM_DIR "/private/var/vm"
#define SWAPFILE "swapfile"

static int sigar_swap_fs_get(sigar_t *sigar, sigar_swap_t *swap) /* <= 10.3 */
{
    DIR *dirp;
    struct dirent *ent;
    char swapfile[SSTRLEN(VM_DIR) + SSTRLEN("/") + SSTRLEN(SWAPFILE) + 12];
    struct stat swapstat;
    struct statfs vmfs;
    sigar_uint64_t val, bsize;

    swap->used = swap->total = swap->free = 0;

    if (!(dirp = opendir(VM_DIR))) {
         return errno;
     }

    /* looking for "swapfile0", "swapfile1", etc. */
    while ((ent = readdir(dirp))) {
        char *ptr = swapfile;

        if ((ent->d_namlen < SSTRLEN(SWAPFILE)+1) || /* n/a, see comment above */
            (ent->d_namlen > SSTRLEN(SWAPFILE)+11)) /* ensure no overflow */
        {
            continue;
        }

        if (!strnEQ(ent->d_name, SWAPFILE, SSTRLEN(SWAPFILE))) {
            continue;
        }

        /* sprintf(swapfile, "%s/%s", VM_DIR, ent->d_name) */

        memcpy(ptr, VM_DIR, SSTRLEN(VM_DIR));
        ptr += SSTRLEN(VM_DIR);

        *ptr++ = '/';

        memcpy(ptr, ent->d_name, ent->d_namlen+1);

        if (stat(swapfile, &swapstat) < 0) {
            continue;
        }

        swap->used += swapstat.st_size;
    }

    closedir(dirp);

    if (statfs(VM_DIR, &vmfs) < 0) {
        return errno;
    }

    bsize = vmfs.f_bsize / 512;
    val = vmfs.f_bfree;
    swap->total = SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) + swap->used;

    swap->free = swap->total - swap->used;

    return SIGAR_OK;
}

static int sigar_swap_sysctl_get(sigar_t *sigar, sigar_swap_t *swap)

{
#ifdef VM_SWAPUSAGE /* => 10.4 */
    struct xsw_usage sw_usage;
    size_t size = sizeof(sw_usage);
    int mib[] = { CTL_VM, VM_SWAPUSAGE };

    if (sysctl(mib, NMIB(mib), &sw_usage, &size, NULL, 0) != 0) {
        return errno;
    }

    swap->total = sw_usage.xsu_total;
    swap->used = sw_usage.xsu_used;
    swap->free = sw_usage.xsu_avail;

    return SIGAR_OK;
#else
    return SIGAR_ENOTIMPL; /* <= 10.3 */
#endif
}

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    int status;
    vm_statistics_data_t vmstat;

    if (sigar_swap_sysctl_get(sigar, swap) != SIGAR_OK) {
        status = sigar_swap_fs_get(sigar, swap); /* <= 10.3 */
        if (status != SIGAR_OK) {
            return status;
        }
    }

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    swap->page_in = vmstat.pageins;
    swap->page_out = vmstat.pageouts;

    return SIGAR_OK;
}

#ifndef KERN_CPTIME
#define KERN_CPTIME KERN_CP_TIME
#endif

typedef time_t cp_time_t;

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    kern_return_t status;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuload;

    status = host_statistics(sigar->mach_port, HOST_CPU_LOAD_INFO,
                             (host_info_t)&cpuload, &count);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    cpu->user = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_USER]);
    cpu->sys  = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_SYSTEM]);
    cpu->idle = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_IDLE]);
    cpu->nice = SIGAR_TICK2MSEC(cpuload.cpu_ticks[CPU_STATE_NICE]);
    cpu->wait = 0; /*N/A*/
    cpu->irq = 0; /*N/A*/
    cpu->soft_irq = 0; /*N/A*/
    cpu->stolen = 0; /*N/A*/
    cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle;

    return SIGAR_OK;
}

int sigar_cpu_list_get(sigar_t *sigar, sigar_cpu_list_t *cpulist)
{
    kern_return_t status;
    mach_msg_type_number_t count;
    processor_cpu_load_info_data_t *cpuload;
    natural_t i, ncpu;

    status = host_processor_info(sigar->mach_port,
                                 PROCESSOR_CPU_LOAD_INFO,
                                 &ncpu,
                                 (processor_info_array_t*)&cpuload,
                                 &count);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    sigar_cpu_list_create(cpulist);

    for (i=0; i<ncpu; i++) {
        sigar_cpu_t *cpu;

        SIGAR_CPU_LIST_GROW(cpulist);

        cpu = &cpulist->data[cpulist->number++];

        cpu->user = SIGAR_TICK2MSEC(cpuload[i].cpu_ticks[CPU_STATE_USER]);
        cpu->sys  = SIGAR_TICK2MSEC(cpuload[i].cpu_ticks[CPU_STATE_SYSTEM]);
        cpu->idle = SIGAR_TICK2MSEC(cpuload[i].cpu_ticks[CPU_STATE_IDLE]);
        cpu->nice = SIGAR_TICK2MSEC(cpuload[i].cpu_ticks[CPU_STATE_NICE]);
        cpu->wait = 0; /*N/A*/
        cpu->irq = 0; /*N/A*/
        cpu->soft_irq = 0; /*N/A*/
        cpu->stolen = 0; /*N/A*/
        cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle;
    }

    vm_deallocate(mach_task_self(), (vm_address_t)cpuload, count);

    return SIGAR_OK;
}

int sigar_uptime_get(sigar_t *sigar,
                     sigar_uptime_t *uptime)
{
    uptime->uptime   = time(NULL) - sigar->boot_time;

    return SIGAR_OK;
}

int sigar_loadavg_get(sigar_t *sigar,
                      sigar_loadavg_t *loadavg)
{
    loadavg->processor_queue = SIGAR_FIELD_NOTIMPL;
    getloadavg(loadavg->loadavg, 3);

    return SIGAR_OK;
}

int sigar_system_stats_get (sigar_t *sigar,
                            sigar_system_stats_t *system_stats)
{
    return SIGAR_ENOTIMPL;
}

#if defined(DARWIN_HAS_LIBPROC_H)

static int proc_fdinfo_get(sigar_t *sigar, sigar_pid_t pid, int *num)
{
    int rsize;
    const int init_size = PROC_PIDLISTFD_SIZE * 32;

#ifdef DARWIN_HAS_LIBPROC_H
    if (!sigar->libproc) {
        return SIGAR_ENOTIMPL;
    }
#endif

    if (sigar->ifconf_len == 0) {
        sigar->ifconf_len = init_size;
        sigar->ifconf_buf = malloc(sigar->ifconf_len);
    }

    while (1) {
        rsize = sigar->proc_pidinfo(pid, PROC_PIDLISTFDS, 0,
                                    sigar->ifconf_buf, sigar->ifconf_len);
        if (rsize <= 0) {
            return errno;
        }
        if ((rsize + PROC_PIDLISTFD_SIZE) < sigar->ifconf_len) {
            break;
        }

        sigar->ifconf_len += init_size;
        sigar->ifconf_buf = realloc(sigar->ifconf_buf, sigar->ifconf_len);
    }

    *num = rsize / PROC_PIDLISTFD_SIZE;

    return SIGAR_OK;
}

#endif

static int proc_fd_get_count(sigar_t *sigar, sigar_pid_t pid, int *num)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    int pinfo_size;
    struct proc_fdinfo *pbuffer;

    if (!sigar->libproc) {
        return SIGAR_ENOTIMPL;
    }

    pinfo_size = sigar->proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);

    if (pinfo_size <= 0) {
        return SIGAR_ENOTIMPL;
    }

    pbuffer = malloc(pinfo_size);
    pinfo_size = sigar->proc_pidinfo(pid, PROC_PIDLISTFDS, 0, pbuffer, pinfo_size);
    free(pbuffer);

    *num = pinfo_size / PROC_PIDLISTFD_SIZE;

    return SIGAR_OK;
#endif
}

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    int i, num;
    size_t len;
    struct kinfo_proc *proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        return errno;
    }

    num = len/sizeof(*proc);

    for (i=0; i<num; i++) {
        if (proc[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        if (proc[i].KI_PID == 0) {
            continue;
        }
        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = proc[i].KI_PID;
    }

    free(proc);

    return SIGAR_OK;
}

static int sigar_get_pinfo(sigar_t *sigar, sigar_pid_t pid)
{
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    size_t len = sizeof(*sigar->pinfo);
    time_t timenow = time(NULL);
    mib[3] = pid;

    if (sigar->pinfo == NULL) {
        sigar->pinfo = malloc(len);
    }

    if (sigar->last_pid == pid) {
        if ((timenow - sigar->last_getprocs) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    sigar->last_pid = pid;
    sigar->last_getprocs = timenow;

    if (sysctl(mib, NMIB(mib), sigar->pinfo, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

#if defined(SHARED_TEXT_REGION_SIZE) && defined(SHARED_DATA_REGION_SIZE)
#  define GLOBAL_SHARED_SIZE (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE) /* 10.4 SDK */
#endif

#if defined(DARWIN_HAS_LIBPROC_H) && !defined(GLOBAL_SHARED_SIZE)
/* get the CPU type of the process for the given pid */
static int sigar_proc_cpu_type(sigar_t *sigar, sigar_pid_t pid, cpu_type_t *type)
{
    int status;
    int mib[CTL_MAXNAME];
    size_t len, miblen = NMIB(mib);

    status = sysctlnametomib("sysctl.proc_cputype", mib, &miblen);
    if (status != SIGAR_OK) {
        return status;
    }

    mib[miblen] = pid;
    len = sizeof(*type);
    return sysctl(mib, miblen + 1, type, &len, NULL, 0);
}

/* shared memory region size for the given cpu_type_t */
static mach_vm_size_t sigar_shared_region_size(cpu_type_t type)
{
    switch (type) {
      case CPU_TYPE_ARM:
        return SHARED_REGION_SIZE_ARM;
      case CPU_TYPE_POWERPC:
        return SHARED_REGION_SIZE_PPC;
      case CPU_TYPE_POWERPC64:
        return SHARED_REGION_SIZE_PPC64;
      case CPU_TYPE_I386:
        return SHARED_REGION_SIZE_I386;
      case CPU_TYPE_X86_64:
        return SHARED_REGION_SIZE_X86_64;
      default:
        return SHARED_REGION_SIZE_I386; /* assume 32-bit x86|ppc */
    }
}
#endif

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
    mach_port_t task, self = mach_task_self();
    kern_return_t status;
    task_basic_info_data_t info;
    task_events_info_data_t events;
    mach_msg_type_number_t count;
#  ifdef DARWIN_HAS_LIBPROC_H
    struct proc_taskinfo pti;
    struct proc_regioninfo pri;

    if (sigar->libproc) {
        int sz =
            sigar->proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));

        if (sz == sizeof(pti)) {
            procmem->size         = pti.pti_virtual_size;
            procmem->resident     = pti.pti_resident_size;
            procmem->page_faults  = pti.pti_faults;
            procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
            procmem->major_faults = SIGAR_FIELD_NOTIMPL;
            procmem->share        = SIGAR_FIELD_NOTIMPL;

            sz = sigar->proc_pidinfo(pid, PROC_PIDREGIONINFO, 0, &pri, sizeof(pri));
            if (sz == sizeof(pri)) {
                if (pri.pri_share_mode == SM_EMPTY) {
                    mach_vm_size_t shared_size;
#ifdef GLOBAL_SHARED_SIZE
                    shared_size = GLOBAL_SHARED_SIZE; /* 10.4 SDK */
#else
                    cpu_type_t cpu_type;

                    if (sigar_proc_cpu_type(sigar, pid, &cpu_type) == SIGAR_OK) {
                        shared_size = sigar_shared_region_size(cpu_type);
                    }
                    else {
                        shared_size = SHARED_REGION_SIZE_I386; /* assume 32-bit x86|ppc */
                    }
#endif
                    if (procmem->size > shared_size) {
                        procmem->size -= shared_size; /* SIGAR-123 */
                    }
                }
            }
            return SIGAR_OK;
        }
    }
#  endif

    status = task_for_pid(self, pid, &task);

    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_BASIC_INFO_COUNT;
    status = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_EVENTS_INFO_COUNT;
    status = task_info(task, TASK_EVENTS_INFO, (task_info_t)&events, &count);
    if (status == KERN_SUCCESS) {
        procmem->page_faults = events.faults;
    }
    else {
        procmem->page_faults = SIGAR_FIELD_NOTIMPL;
    }

    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;

    if (task != self) {
        mach_port_deallocate(self, task);
    }

    procmem->size     = info.virtual_size;
    procmem->resident = info.resident_size;
    procmem->share    = SIGAR_FIELD_NOTIMPL;

    return SIGAR_OK;
}

int sigar_proc_cumulative_disk_io_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_cumulative_disk_io_t *proc_cumulative_disk_io)
{
    return SIGAR_ENOTIMPL;
}


int sigar_proc_cred_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_cred_t *proccred)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    proccred->uid  = pinfo->KI_UID;
    proccred->gid  = pinfo->KI_GID;
    proccred->euid = pinfo->KI_EUID;
    proccred->egid = pinfo->KI_EGID;

    return SIGAR_OK;
}

#define tv2msec(tv) \
   (((sigar_uint64_t)tv.tv_sec * SIGAR_MSEC) + (((sigar_uint64_t)tv.tv_usec) / 1000))

#define tval2msec(tval) \
   ((tval.seconds * SIGAR_MSEC) + (tval.microseconds / 1000))

#define tval2nsec(tval) \
    (SIGAR_SEC2NANO((tval).seconds) + SIGAR_MICROSEC2NANO((tval).microseconds))

static int get_proc_times(sigar_t *sigar, sigar_pid_t pid, sigar_proc_time_t *time)
{
    unsigned int count;
    time_value_t utime = {0, 0}, stime = {0, 0};
    task_basic_info_data_t ti;
    task_thread_times_info_data_t tti;
    task_port_t task, self;
    kern_return_t status;
#  ifdef DARWIN_HAS_LIBPROC_H
    if (sigar->libproc) {
        struct proc_taskinfo pti;
        int sz =
            sigar->proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti));

        if (sz == sizeof(pti)) {
            time->user = SIGAR_NSEC2MSEC(pti.pti_total_user);
            time->sys  = SIGAR_NSEC2MSEC(pti.pti_total_system);
            time->total = time->user + time->sys;
            return SIGAR_OK;
        }
    }
#  endif

    self = mach_task_self();
    status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    count = TASK_BASIC_INFO_COUNT;
    status = task_info(task, TASK_BASIC_INFO,
                       (task_info_t)&ti, &count);
    if (status != KERN_SUCCESS) {
        if (task != self) {
            mach_port_deallocate(self, task);
        }
        return errno;
    }

    count = TASK_THREAD_TIMES_INFO_COUNT;
    status = task_info(task, TASK_THREAD_TIMES_INFO,
                       (task_info_t)&tti, &count);
    if (status != KERN_SUCCESS) {
        if (task != self) {
            mach_port_deallocate(self, task);
        }
        return errno;
    }

    time_value_add(&utime, &ti.user_time);
    time_value_add(&stime, &ti.system_time);
    time_value_add(&utime, &tti.user_time);
    time_value_add(&stime, &tti.system_time);

    time->user = tval2msec(utime);
    time->sys  = tval2msec(stime);
    time->total = time->user + time->sys;

    return SIGAR_OK;
}

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    if ((status = get_proc_times(sigar, pid, proctime)) != SIGAR_OK) {
        return status;
    }
    proctime->start_time = tv2msec(pinfo->KI_START);

    return SIGAR_OK;
}

/* thread state mapping derived from ps.tproj */
static const char thread_states[] = {
    /*0*/ '-',
    /*1*/ SIGAR_PROC_STATE_RUN,
    /*2*/ SIGAR_PROC_STATE_ZOMBIE,
    /*3*/ SIGAR_PROC_STATE_SLEEP,
    /*4*/ SIGAR_PROC_STATE_IDLE,
    /*5*/ SIGAR_PROC_STATE_STOP,
    /*6*/ SIGAR_PROC_STATE_STOP,
    /*7*/ '?'
};

static int thread_state_get(thread_basic_info_data_t *info)
{
    switch (info->run_state) {
      case TH_STATE_RUNNING:
        return 1;
      case TH_STATE_UNINTERRUPTIBLE:
        return 2;
      case TH_STATE_WAITING:
        return (info->sleep_time > 20) ? 4 : 3;
      case TH_STATE_STOPPED:
        return 5;
      case TH_STATE_HALTED:
        return 6;
      default:
        return 7;
    }
}

static int sigar_proc_threads_get(sigar_t *sigar, sigar_pid_t pid,
                                  sigar_proc_state_t *procstate)
{
    mach_port_t task, self = mach_task_self();
    kern_return_t status;
    thread_array_t threads;
    mach_msg_type_number_t count, i;
    int state = TH_STATE_HALTED + 1;

    status = task_for_pid(self, pid, &task);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    procstate->threads = count;

    for (i=0; i<count; i++) {
        mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
        thread_basic_info_data_t info;

        status = thread_info(threads[i], THREAD_BASIC_INFO,
                             (thread_info_t)&info, &info_count);
        if (status == KERN_SUCCESS) {
            int tstate = thread_state_get(&info);
            if (tstate < state) {
                state = tstate;
            }
        }
    }

    vm_deallocate(self, (vm_address_t)threads, sizeof(thread_t) * count);

    procstate->state = thread_states[state];

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;
    int state = pinfo->KI_STAT;

    if (status != SIGAR_OK) {
        return status;
    }

    procstate->open_files = SIGAR_FIELD_NOTIMPL;

    SIGAR_SSTRCPY(procstate->name, pinfo->KI_COMM);
    procstate->ppid     = pinfo->KI_PPID;
    procstate->priority = pinfo->KI_PRI;
    procstate->nice     = pinfo->KI_NICE;
    procstate->tty      = SIGAR_FIELD_NOTIMPL; /*XXX*/
    procstate->threads  = SIGAR_FIELD_NOTIMPL;
    procstate->processor = SIGAR_FIELD_NOTIMPL;

    int num = 0;
    status = proc_fd_get_count(sigar, pid, &num);
    if (status == SIGAR_OK) {
        procstate->open_files = num;
    }

    status = sigar_proc_threads_get(sigar, pid, procstate);
    if (status == SIGAR_OK) {
        return status;
    }

    switch (state) {
      case SIDL:
        procstate->state = 'D';
        break;
      case SRUN:
#ifdef SONPROC
      case SONPROC:
#endif
        procstate->state = 'R';
        break;
      case SSLEEP:
        procstate->state = 'S';
        break;
      case SSTOP:
        procstate->state = 'T';
        break;
      case SZOMB:
        procstate->state = 'Z';
        break;
      default:
        procstate->state = '?';
        break;
    }

    return SIGAR_OK;
}

typedef struct {
    char *buf, *ptr, *end;
    int count;
} sigar_kern_proc_args_t;

static void sigar_kern_proc_args_destroy(sigar_kern_proc_args_t *kargs)
{
    if (kargs->buf) {
        free(kargs->buf);
        kargs->buf = NULL;
    }
}

/* re-usable hack for use by proc_args and proc_env */
static int sigar_kern_proc_args_get(sigar_t *sigar,
                                    sigar_pid_t pid,
                                    char *exe,
                                    sigar_kern_proc_args_t *kargs)
{
    /*
     * derived from:
     * http://darwinsource.opendarwin.org/10.4.1/adv_cmds-79.1/ps.tproj/print.c
     */
    int mib[3], len;
    size_t size = sigar_argmax_get(sigar);

    kargs->buf = malloc(size);

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2;
    mib[2] = pid;

    if (sysctl(mib, NMIB(mib), kargs->buf, &size, NULL, 0) < 0) {
        sigar_kern_proc_args_destroy(kargs);
        return errno;
    }

    kargs->end = &kargs->buf[size];

    memcpy(&kargs->count, kargs->buf, sizeof(kargs->count));
    kargs->ptr = kargs->buf + sizeof(kargs->count);

    len = strlen(kargs->ptr);
    if (exe) {
        memcpy(exe, kargs->ptr, len+1);
    }
    kargs->ptr += len+1;

    if (kargs->ptr == kargs->end) {
        sigar_kern_proc_args_destroy(kargs);
        return exe ? SIGAR_OK : ENOENT;
    }

    for (; kargs->ptr < kargs->end; kargs->ptr++) {
        if (*kargs->ptr != '\0') {
            break; /* start of argv[0] */
        }
    }

    if (kargs->ptr == kargs->end) {
        sigar_kern_proc_args_destroy(kargs);
        return exe ? SIGAR_OK : ENOENT;
    }

    return SIGAR_OK;
}

static int kern_proc_args_skip_argv(sigar_kern_proc_args_t *kargs)
{
    char *ptr = kargs->ptr;
    char *end = kargs->end;
    int count = kargs->count;

    /* skip over argv */
    while ((ptr < end) && (count-- > 0)) {
        int alen = strlen(ptr)+1;

        ptr += alen;
    }

    kargs->ptr = ptr;
    kargs->end = end;
    kargs->count = 0;

    if (ptr >= end) {
        return ENOENT;
    }

    return SIGAR_OK;
}

int sigar_os_proc_args_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_args_t *procargs)
{
    int status, count;
    sigar_kern_proc_args_t kargs;
    char *ptr, *end;

    status = sigar_kern_proc_args_get(sigar, pid, NULL, &kargs);
    if (status != SIGAR_OK) {
        return status;
    }

    count = kargs.count;
    ptr = kargs.ptr;
    end = kargs.end;

    while ((ptr < end) && (count-- > 0)) {
        int slen = strlen(ptr);
        int alen = slen+1;
        char *arg;

        /*
         * trim trailing whitespace.
         * seen w/ postgresql, probably related
         * to messing with argv[0]
         */
        while (*(ptr + (slen-1)) == ' ') {
            if (--slen <= 0) {
                break;
            }
        }

        arg = malloc(slen+1);

        SIGAR_PROC_ARGS_GROW(procargs);
        memcpy(arg, ptr, slen);
        *(arg+slen) = '\0';

        procargs->data[procargs->number++] = arg;

        ptr += alen;
    }

    sigar_kern_proc_args_destroy(&kargs);
    return SIGAR_OK;
}

int sigar_proc_env_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_env_t *procenv)
{
    int status, count;
    sigar_kern_proc_args_t kargs;
    char *ptr, *end;

    status = sigar_kern_proc_args_get(sigar, pid, NULL, &kargs);
    if (status != SIGAR_OK) {
        return status;
    }

    status = kern_proc_args_skip_argv(&kargs);
    if (status != SIGAR_OK) {
        sigar_kern_proc_args_destroy(&kargs);
        return status;
    }

    count = kargs.count;
    ptr = kargs.ptr;
    end = kargs.end;

    /* into environ */
    while (ptr < end) {
        char *val = strchr(ptr, '=');
        int klen, vlen, status;
        char key[256]; /* XXX is there a max key size? */

        if (val == NULL) {
            /* not key=val format */
            break;
        }

        klen = val - ptr;
        SIGAR_SSTRCPY(key, ptr);
        key[klen] = '\0';
        ++val;

        vlen = strlen(val);
        status = procenv->env_getter(procenv->data,
                                     key, klen, val, vlen);

        if (status != SIGAR_OK) {
            /* not an error; just stop iterating */
            break;
        }

        ptr += (klen + 1 + vlen + 1);

        if (*ptr == '\0') {
            break;
        }
    }

    sigar_kern_proc_args_destroy(&kargs);
    return SIGAR_OK;
}

int sigar_proc_fd_get(sigar_t *sigar, sigar_pid_t pid,
                      sigar_proc_fd_t *procfd)
{
    return SIGAR_ENOTIMPL;
}

int sigar_proc_exe_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_exe_t *procexe)
{
    memset(procexe, 0, sizeof(*procexe));

    int status;
    sigar_kern_proc_args_t kargs;

    status = sigar_kern_proc_args_get(sigar, pid, procexe->name, &kargs);
    if (status == SIGAR_OK) {
        /* attempt to determine cwd from $PWD */
        status = kern_proc_args_skip_argv(&kargs);
        if (status == SIGAR_OK) {
            char *ptr = kargs.ptr;
            char *end = kargs.end;

            /* into environ */
            while (ptr < end) {
                int len = strlen(ptr);

                if ((len > 4) &&
                    (ptr[0] == 'P') &&
                    (ptr[1] == 'W') &&
                    (ptr[2] == 'D') &&
                    (ptr[3] == '='))
                {
                    memcpy(procexe->cwd, ptr+4, len-3);
                    break;
                }

                ptr += len+1;
            }
        }

        sigar_kern_proc_args_destroy(&kargs);
    }

    // XXX do we need to read mach-o, or is there a better way?
    procexe->arch = sigar->arch;

    return SIGAR_OK;
}

static int sigar_dlinfo_modules(sigar_t *sigar, sigar_proc_modules_t *procmods)
{
    uint32_t i, count = _dyld_image_count();

    for (i=0; i<count; i++) {
        int status;
        const char *name =
            _dyld_get_image_name(i);

        if (name == NULL) {
            continue;
        }
        status =
            procmods->module_getter(procmods->data,
                                    (char *)name, strlen(name));

        if (status != SIGAR_OK) {
            /* not an error; just stop iterating */
            break;
        }
    }
    return SIGAR_OK;
}

int sigar_proc_modules_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_modules_t *procmods)
{
    if (pid == sigar_pid_get(sigar)) {
        return sigar_dlinfo_modules(sigar, procmods);
    }
    return SIGAR_ENOTIMPL;
}

#define SIGAR_MICROSEC2NANO(s) \
    ((sigar_uint64_t)(s) * (sigar_uint64_t)1000)

#define TIME_NSEC(t) \
    (SIGAR_SEC2NANO((t).tv_sec) + SIGAR_MICROSEC2NANO((t).tv_usec))

int sigar_thread_cpu_get(sigar_t *sigar,
                         sigar_uint64_t id,
                         sigar_thread_cpu_t *cpu)
{
    mach_port_t self = mach_thread_self();
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    kern_return_t status;

    status = thread_info(self, THREAD_BASIC_INFO,
                         (thread_info_t)&info, &count);
    if (status != KERN_SUCCESS) {
        return errno;
    }

    mach_port_deallocate(mach_task_self(), self);

    cpu->user  = tval2nsec(info.user_time);
    cpu->sys   = tval2nsec(info.system_time);
    cpu->total = cpu->user + cpu->sys;

    return SIGAR_OK;
}

int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    /* see sys/disklabel.h */
    switch (*type) {
      case 'f':
        if (strEQ(type, "ffs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'h':
        if (strEQ(type, "hfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'u':
        if (strEQ(type, "ufs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
    }

    return fsp->type;
}

static void get_fs_options(char *opts, int osize, long flags)
{
    *opts = '\0';
    if (flags & MNT_RDONLY)         strncat(opts, "ro", osize);
    else                            strncat(opts, "rw", osize);
    if (flags & MNT_SYNCHRONOUS)    strncat(opts, ",sync", osize);
    if (flags & MNT_NOEXEC)         strncat(opts, ",noexec", osize);
    if (flags & MNT_NOSUID)         strncat(opts, ",nosuid", osize);
#ifdef MNT_NODEV
    if (flags & MNT_NODEV)          strncat(opts, ",nodev", osize);
#endif
#ifdef MNT_UNION
    if (flags & MNT_UNION)          strncat(opts, ",union", osize);
#endif
    if (flags & MNT_ASYNC)          strncat(opts, ",async", osize);
#ifdef MNT_NOATIME
    if (flags & MNT_NOATIME)        strncat(opts, ",noatime", osize);
#endif
#ifdef MNT_NOCLUSTERR
    if (flags & MNT_NOCLUSTERR)     strncat(opts, ",noclusterr", osize);
#endif
#ifdef MNT_NOCLUSTERW
    if (flags & MNT_NOCLUSTERW)     strncat(opts, ",noclusterw", osize);
#endif
#ifdef MNT_NOSYMFOLLOW
    if (flags & MNT_NOSYMFOLLOW)    strncat(opts, ",nosymfollow", osize);
#endif
#ifdef MNT_SUIDDIR
    if (flags & MNT_SUIDDIR)        strncat(opts, ",suiddir", osize);
#endif
#ifdef MNT_SOFTDEP
    if (flags & MNT_SOFTDEP)        strncat(opts, ",soft-updates", osize);
#endif
    if (flags & MNT_LOCAL)          strncat(opts, ",local", osize);
    if (flags & MNT_QUOTA)          strncat(opts, ",quota", osize);
    if (flags & MNT_ROOTFS)         strncat(opts, ",rootfs", osize);
#ifdef MNT_USER
    if (flags & MNT_USER)           strncat(opts, ",user", osize);
#endif
#ifdef MNT_IGNORE
    if (flags & MNT_IGNORE)         strncat(opts, ",ignore", osize);
#endif
    if (flags & MNT_EXPORTED)       strncat(opts, ",nfs", osize);
}

#define sigar_statfs statfs
#define sigar_getfsstat getfsstat
#define sigar_f_flags f_flags

int sigar_file_system_list_get(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    struct sigar_statfs *fs;
    int num, i;
    int is_debug = SIGAR_LOG_IS_DEBUG(sigar);
    long len;

    if ((num = sigar_getfsstat(NULL, 0, MNT_NOWAIT)) < 0) {
        return errno;
    }

    len = sizeof(*fs) * num;
    fs = malloc(len);

    if ((num = sigar_getfsstat(fs, len, MNT_NOWAIT)) < 0) {
        free(fs);
        return errno;
    }

    sigar_file_system_list_create(fslist);

    for (i=0; i<num; i++) {
        sigar_file_system_t *fsp;

#ifdef MNT_AUTOMOUNTED
        if (fs[i].sigar_f_flags & MNT_AUTOMOUNTED) {
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping automounted %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

#ifdef MNT_RDONLY
        if (fs[i].sigar_f_flags & MNT_RDONLY) {
            /* e.g. ftp mount or .dmg image */
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping readonly %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        SIGAR_SSTRCPY(fsp->dir_name, fs[i].f_mntonname);
        SIGAR_SSTRCPY(fsp->dev_name, fs[i].f_mntfromname);
        SIGAR_SSTRCPY(fsp->sys_type_name, fs[i].f_fstypename);
        get_fs_options(fsp->options, sizeof(fsp->options)-1, fs[i].sigar_f_flags);

        sigar_fs_type_init(fsp);
    }

    free(fs);
    return SIGAR_OK;
}

#define IoStatGetValue(key, val) \
    if ((number = (CFNumberRef)CFDictionaryGetValue(stats, CFSTR(kIOBlockStorageDriverStatistics##key)))) \
        CFNumberGetValue(number, kCFNumberSInt64Type, &val)

int sigar_disk_usage_get(sigar_t *sigar, const char *name,
                         sigar_disk_usage_t *disk)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    kern_return_t status;
    io_registry_entry_t parent;
    io_service_t service;
    CFDictionaryRef props;
    CFNumberRef number;
    sigar_iodev_t *iodev = sigar_iodev_get(sigar, name);
    char dname[256], *ptr;

    SIGAR_DISK_STATS_INIT(disk);

    if (!iodev) {
        return ENXIO;
    }

    /* "/dev/disk0s1" -> "disk0" */ /* XXX better way? */
    ptr = &iodev->name[SSTRLEN(SIGAR_DEV_PREFIX)];
    SIGAR_SSTRCPY(dname, ptr);
    ptr = dname;
    if (strnEQ(ptr, "disk", 4)) {
        ptr += 4;
        if ((ptr = strchr(ptr, 's')) && isdigit(*(ptr+1))) {
            *ptr = '\0';
        }
    }

    if (SIGAR_LOG_IS_DEBUG(sigar)) {
        sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                         "[disk_usage] map %s -> %s",
                         iodev->name, dname);
    }

    /* e.g. name == "disk0" */
    service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                          IOBSDNameMatching(kIOMasterPortDefault, 0, dname));

    if (!service) {
        return errno;
    }

    status = IORegistryEntryGetParentEntry(service, kIOServicePlane, &parent);
    if (status != KERN_SUCCESS) {
        IOObjectRelease(service);
        return status;
    }

    status = IORegistryEntryCreateCFProperties(parent,
                                               (CFMutableDictionaryRef *)&props,
                                               kCFAllocatorDefault,
                                               kNilOptions);
    if (props) {
        CFDictionaryRef stats =
            (CFDictionaryRef)CFDictionaryGetValue(props,
                                                  CFSTR(kIOBlockStorageDriverStatisticsKey));

        if (stats) {
            IoStatGetValue(ReadsKey, disk->reads);
            IoStatGetValue(BytesReadKey, disk->read_bytes);
            IoStatGetValue(TotalReadTimeKey, disk->rtime);
            IoStatGetValue(WritesKey, disk->writes);
            IoStatGetValue(BytesWrittenKey, disk->write_bytes);
            IoStatGetValue(TotalWriteTimeKey, disk->wtime);
            disk->time = disk->rtime + disk->wtime;
        }

        CFRelease(props);
    }

    IOObjectRelease(service);
    IOObjectRelease(parent);

    return SIGAR_OK;
#endif
}

int sigar_file_system_usage_get(sigar_t *sigar,
                                const char *dirname,
                                sigar_file_system_usage_t *fsusage)
{
    int status = sigar_statvfs(sigar, dirname, fsusage);

    if (status != SIGAR_OK) {
        return status;
    }

    fsusage->use_percent = sigar_file_system_usage_calc_used(sigar, fsusage);

    sigar_disk_usage_get(sigar, dirname, &fsusage->disk);

    return SIGAR_OK;
}

#define CTL_HW_FREQ_MAX "hw.cpufrequency_max"
#define CTL_HW_FREQ_MIN "hw.cpufrequency_min"

int sigar_cpu_info_list_get(sigar_t *sigar,
                            sigar_cpu_info_list_t *cpu_infos)
{
    int i;
    unsigned int mhz, mhz_min, mhz_max;
    int cache_size=SIGAR_FIELD_NOTIMPL;
    size_t size;
    char model[128], vendor[128], *ptr;

    size = sizeof(mhz);

    (void)sigar_cpu_core_count(sigar);

    {
        int mib[] = { CTL_HW, HW_CPU_FREQ };
        size = sizeof(mhz);
        if (sysctl(mib, NMIB(mib), &mhz, &size, NULL, 0) < 0) {
            mhz = SIGAR_FIELD_NOTIMPL;
        }
    }
    if (sysctlbyname(CTL_HW_FREQ_MAX, &mhz_max, &size, NULL, 0) < 0) {
        mhz_max = SIGAR_FIELD_NOTIMPL;
    }
    if (sysctlbyname(CTL_HW_FREQ_MIN, &mhz_min, &size, NULL, 0) < 0) {
        mhz_min = SIGAR_FIELD_NOTIMPL;
    }
    if (mhz != SIGAR_FIELD_NOTIMPL) {
        mhz /= 1000000;
    }
    if (mhz_max != SIGAR_FIELD_NOTIMPL) {
        mhz_max /= 1000000;
    }
    if (mhz_min != SIGAR_FIELD_NOTIMPL) {
        mhz_min /= 1000000;
    }

    size = sizeof(model);
    if (sysctlbyname("hw.model", &model, &size, NULL, 0) < 0) {
        int mib[] = { CTL_HW, HW_MODEL };
        size = sizeof(model);
        if (sysctl(mib, NMIB(mib), &model[0], &size, NULL, 0) < 0) {
            strcpy(model, "Unknown");
        }
    }

    if (mhz == SIGAR_FIELD_NOTIMPL) {
        /* freebsd4 */
        mhz = sigar_cpu_mhz_from_model(model);
    }
    /* XXX not sure */
    if (mhz_max == SIGAR_FIELD_NOTIMPL) {
        mhz_max = 0;
    }
    if (mhz_min == SIGAR_FIELD_NOTIMPL) {
        mhz_min = 0;
    }

    size = sizeof(vendor);
    if (sysctlbyname("machdep.cpu.vendor", &vendor, &size, NULL, 0) < 0) {
        SIGAR_SSTRCPY(vendor, "Apple");
    }
    else {
        /* GenuineIntel -> Intel */
        if (strstr(vendor, "Intel")) {
            SIGAR_SSTRCPY(vendor, "Intel");
        }
    }

    if ((ptr = strchr(model, ' '))) {
        if (strstr(model, "Intel")) {
            SIGAR_SSTRCPY(vendor, "Intel");
        }
        else if (strstr(model, "AMD")) {
            SIGAR_SSTRCPY(vendor, "AMD");
        }
        else {
            SIGAR_SSTRCPY(vendor, "Unknown");
        }
        SIGAR_SSTRCPY(model, ptr+1);
    }

    {
        int mib[] = { CTL_HW, HW_L2CACHESIZE }; /* in bytes */
        size = sizeof(cache_size);
        if (sysctl(mib, NMIB(mib), &cache_size, &size, NULL, 0) < 0) {
            cache_size = SIGAR_FIELD_NOTIMPL;
        }
        else {
            cache_size /= 1024; /* convert to KB */
        }
    }

    sigar_cpu_info_list_create(cpu_infos);

    for (i=0; i<sigar->ncpu; i++) {
        sigar_cpu_info_t *info;

        SIGAR_CPU_INFO_LIST_GROW(cpu_infos);

        info = &cpu_infos->data[cpu_infos->number++];

        SIGAR_SSTRCPY(info->vendor, vendor);
        SIGAR_SSTRCPY(info->model, model);
        sigar_cpu_model_adjust(sigar, info);

        info->mhz = mhz;
        info->mhz_max = mhz_max;
        info->mhz_min = mhz_min;
        info->cache_size = cache_size;
        info->total_cores = sigar->ncpu;
        info->cores_per_socket = sigar->lcpu;
        info->total_sockets = sigar_cpu_socket_count(sigar);
    }

    return SIGAR_OK;
}

#define rt_s_addr(sa) ((struct sockaddr_in *)(sa))->sin_addr.s_addr

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

int sigar_net_route_list_get(sigar_t *sigar,
                             sigar_net_route_list_t *routelist)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    size_t needed;
    int bit;
    char *buf, *next, *lim;
    struct rt_msghdr *rtm;
    int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };

    if (sysctl(mib, NMIB(mib), NULL, &needed, NULL, 0) < 0) {
        return errno;
    }
    buf = malloc(needed);

    if (sysctl(mib, NMIB(mib), buf, &needed, NULL, 0) < 0) {
        free(buf);
        return errno;
    }

    sigar_net_route_list_create(routelist);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        struct sockaddr *sa;
        sigar_net_route_t *route;
        rtm = (struct rt_msghdr *)next;

        if (rtm->rtm_type != RTM_GET) {
            continue;
        }

        sa = (struct sockaddr *)(rtm + 1);

        if (sa->sa_family != AF_INET) {
            continue;
        }

        SIGAR_NET_ROUTE_LIST_GROW(routelist);
        route = &routelist->data[routelist->number++];
        SIGAR_ZERO(route);

        route->flags = rtm->rtm_flags;
        if_indextoname(rtm->rtm_index, route->ifname);

        for (bit=RTA_DST;
             bit && ((char *)sa < lim);
             bit <<= 1)
        {
            if ((rtm->rtm_addrs & bit) == 0) {
                continue;
            }
            switch (bit) {
              case RTA_DST:
                sigar_net_address_set(route->destination,
                                      rt_s_addr(sa));
                break;
              case RTA_GATEWAY:
                if (sa->sa_family == AF_INET) {
                    sigar_net_address_set(route->gateway,
                                          rt_s_addr(sa));
                }
                break;
              case RTA_NETMASK:
                sigar_net_address_set(route->mask,
                                      rt_s_addr(sa));
                break;
              case RTA_IFA:
                break;
            }

            sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
        }
    }

    free(buf);

    return SIGAR_OK;
#endif
}

typedef enum {
    IFMSG_ITER_LIST,
    IFMSG_ITER_GET
} ifmsg_iter_e;

typedef struct {
    const char *name;
    ifmsg_iter_e type;
    union {
        sigar_net_interface_list_t *iflist;
        struct if_msghdr *ifm;
    } data;
} ifmsg_iter_t;

static int sigar_ifmsg_init(sigar_t *sigar)
{
    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_IFLIST, 0 };
    size_t len;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    if (sigar->ifconf_len < len) {
        sigar->ifconf_buf = realloc(sigar->ifconf_buf, len);
        sigar->ifconf_len = len;
    }

    if (sysctl(mib, NMIB(mib), sigar->ifconf_buf, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

/**
 * @param name name of the interface
 * @param name_len length of name (w/o \0)
 */
static int has_ifaddr(char *name, size_t name_len)
{
    int sock, status;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }
    strncpy(ifr.ifr_name, name, MIN(sizeof(ifr.ifr_name) - 1, name_len));
    ifr.ifr_name[MIN(sizeof(ifr.ifr_name) - 1, name_len)] = '\0';
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        status = SIGAR_OK;
    }
    else {
        status = errno;
    }

    close(sock);
    return status;
}

static int sigar_ifmsg_iter(sigar_t *sigar, ifmsg_iter_t *iter)
{
    char *end = sigar->ifconf_buf + sigar->ifconf_len;
    char *ptr = sigar->ifconf_buf;

    if (iter->type == IFMSG_ITER_LIST) {
        sigar_net_interface_list_create(iter->data.iflist);
    }

    while (ptr < end) {
        char *name;
        struct sockaddr_dl *sdl;
        struct if_msghdr *ifm = (struct if_msghdr *)ptr;

        if (ifm->ifm_type != RTM_IFINFO) {
            break;
        }

        ptr += ifm->ifm_msglen;

        while (ptr < end) {
            struct if_msghdr *next = (struct if_msghdr *)ptr;

            if (next->ifm_type != RTM_NEWADDR) {
                break;
            }

            ptr += next->ifm_msglen;
        }

        sdl = (struct sockaddr_dl *)(ifm + 1);
        if (sdl->sdl_family != AF_LINK) {
            continue;
        }

        switch (iter->type) {
          case IFMSG_ITER_LIST:
            if (sdl->sdl_type == IFT_OTHER) {
                if (has_ifaddr(sdl->sdl_data, sdl->sdl_nlen) != SIGAR_OK) {
                    break;
                }
            }
            else if (!((sdl->sdl_type == IFT_ETHER) ||
                       (sdl->sdl_type == IFT_LOOP)))
            {
                break; /* XXX deal w/ other weirdo interfaces */
            }

            SIGAR_NET_IFLIST_GROW(iter->data.iflist);

            /* sdl_data doesn't include a trailing \0, it is only sdl_nlen long */
            name = malloc(sdl->sdl_nlen+1);
            memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
            name[sdl->sdl_nlen] = '\0'; /* add the missing \0 */

            iter->data.iflist->data[iter->data.iflist->number++] = name;
            break;

          case IFMSG_ITER_GET:
            if (strlen(iter->name) == sdl->sdl_nlen && 0 == memcmp(iter->name, sdl->sdl_data, sdl->sdl_nlen)) {
                iter->data.ifm = ifm;
                return SIGAR_OK;
            }
        }
    }

    switch (iter->type) {
      case IFMSG_ITER_LIST:
        return SIGAR_OK;

      case IFMSG_ITER_GET:
      default:
        return ENXIO;
    }
}

int sigar_net_interface_list_get(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist)
{
    int status;
    ifmsg_iter_t iter;

    if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
        return status;
    }

    iter.type = IFMSG_ITER_LIST;
    iter.data.iflist = iflist;

    return sigar_ifmsg_iter(sigar, &iter);
}

#include <ifaddrs.h>

/* in6_prefixlen derived from freebsd/sbin/ifconfig/af_inet6.c */
static int sigar_in6_prefixlen(struct sockaddr *netmask)
{
    struct in6_addr *addr = SIGAR_SIN6_ADDR(netmask);
    u_char *name = (u_char *)addr;
    int size = sizeof(*addr);
    int byte, bit, plen = 0;

    for (byte = 0; byte < size; byte++, plen += 8) {
        if (name[byte] != 0xff) {
            break;
        }
    }
    if (byte == size) {
        return plen;
    }
    for (bit = 7; bit != 0; bit--, plen++) {
        if (!(name[byte] & (1 << bit))) {
            break;
        }
    }
    for (; bit != 0; bit--) {
        if (name[byte] & (1 << bit)) {
            return 0;
        }
    }
    byte++;
    for (; byte < size; byte++) {
        if (name[byte]) {
            return 0;
        }
    }
    return plen;
}

int sigar_net_interface_ipv6_config_get(sigar_t *sigar, const char *name,
                                        sigar_net_interface_config_t *ifconfig)
{
    int status = SIGAR_ENOENT;
    struct ifaddrs *addrs, *ifa;

    if (getifaddrs(&addrs) != 0) {
        return errno;
    }

    for (ifa=addrs; ifa; ifa=ifa->ifa_next) {
        if (ifa->ifa_addr &&
            (ifa->ifa_addr->sa_family == AF_INET6) &&
            strEQ(ifa->ifa_name, name))
        {
            status = SIGAR_OK;
            break;
        }
    }

    if (status == SIGAR_OK) {
        struct in6_addr *addr = SIGAR_SIN6_ADDR(ifa->ifa_addr);

        sigar_net_address6_set(ifconfig->address6, addr);
        sigar_net_interface_scope6_set(ifconfig, addr);
        ifconfig->prefix6_length = sigar_in6_prefixlen(ifa->ifa_netmask);
    }

    freeifaddrs(addrs);

    return status;
}

int sigar_net_interface_config_get(sigar_t *sigar, const char *name,
                                   sigar_net_interface_config_t *ifconfig)
{
    int sock;
    int status;
    ifmsg_iter_t iter;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;
    struct ifreq ifr;

    if (!name) {
        return sigar_net_interface_config_primary_get(sigar, ifconfig);
    }

    if (sigar->ifconf_len == 0) {
        if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
            return status;
        }
    }

    SIGAR_ZERO(ifconfig);

    iter.type = IFMSG_ITER_GET;
    iter.name = name;

    if ((status = sigar_ifmsg_iter(sigar, &iter)) != SIGAR_OK) {
        return status;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    ifm = iter.data.ifm;

    SIGAR_SSTRCPY(ifconfig->name, name);

    sdl = (struct sockaddr_dl *)(ifm + 1);

    sigar_net_address_mac_set(ifconfig->hwaddr,
                              LLADDR(sdl),
                              sdl->sdl_alen);

    ifconfig->flags = ifm->ifm_flags;
    ifconfig->mtu = ifm->ifm_data.ifi_mtu;
    ifconfig->metric = ifm->ifm_data.ifi_metric;

    SIGAR_SSTRCPY(ifr.ifr_name, name);

#define ifr_s_addr(ifr) \
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr

    if (!ioctl(sock, SIOCGIFADDR, &ifr)) {
        sigar_net_address_set(ifconfig->address,
                              ifr_s_addr(ifr));
    }

    if (!ioctl(sock, SIOCGIFNETMASK, &ifr)) {
        sigar_net_address_set(ifconfig->netmask,
                              ifr_s_addr(ifr));
    }

    if (ifconfig->flags & IFF_LOOPBACK) {
        sigar_net_address_set(ifconfig->destination,
                              ifconfig->address.addr.in);
        sigar_net_address_set(ifconfig->broadcast, 0);
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_LOOPBACK);
    }
    else {
        if (!ioctl(sock, SIOCGIFDSTADDR, &ifr)) {
            sigar_net_address_set(ifconfig->destination,
                                  ifr_s_addr(ifr));
        }

        if (!ioctl(sock, SIOCGIFBRDADDR, &ifr)) {
            sigar_net_address_set(ifconfig->broadcast,
                                  ifr_s_addr(ifr));
        }
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
    }

    close(sock);

    /* XXX can we get a better description like win32? */
    SIGAR_SSTRCPY(ifconfig->description,
                  ifconfig->name);

    sigar_net_interface_ipv6_config_init(ifconfig);
    sigar_net_interface_ipv6_config_get(sigar, name, ifconfig);

    return SIGAR_OK;
}

int sigar_net_interface_stat_get(sigar_t *sigar, const char *name,
                                 sigar_net_interface_stat_t *ifstat)
{
    int status;
    ifmsg_iter_t iter;
    struct if_msghdr *ifm;

    if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
        return status;
    }

    iter.type = IFMSG_ITER_GET;
    iter.name = name;

    if ((status = sigar_ifmsg_iter(sigar, &iter)) != SIGAR_OK) {
        return status;
    }

    ifm = iter.data.ifm;

    ifstat->rx_bytes      = ifm->ifm_data.ifi_ibytes;
    ifstat->rx_packets    = ifm->ifm_data.ifi_ipackets;
    ifstat->rx_errors     = ifm->ifm_data.ifi_ierrors;
    ifstat->rx_dropped    = ifm->ifm_data.ifi_iqdrops;
    ifstat->rx_overruns   = SIGAR_FIELD_NOTIMPL;
    ifstat->rx_frame      = SIGAR_FIELD_NOTIMPL;

    ifstat->tx_bytes      = ifm->ifm_data.ifi_obytes;
    ifstat->tx_packets    = ifm->ifm_data.ifi_opackets;
    ifstat->tx_errors     = ifm->ifm_data.ifi_oerrors;
    ifstat->tx_collisions = ifm->ifm_data.ifi_collisions;
    ifstat->tx_dropped    = SIGAR_FIELD_NOTIMPL;
    ifstat->tx_overruns   = SIGAR_FIELD_NOTIMPL;
    ifstat->tx_carrier    = SIGAR_FIELD_NOTIMPL;

    ifstat->speed         = ifm->ifm_data.ifi_baudrate;

    return SIGAR_OK;
}

static int net_connection_state_get(int state)
{
    switch (state) {
      case TCPS_CLOSED:
        return SIGAR_TCP_CLOSE;
      case TCPS_LISTEN:
        return SIGAR_TCP_LISTEN;
      case TCPS_SYN_SENT:
        return SIGAR_TCP_SYN_SENT;
      case TCPS_SYN_RECEIVED:
        return SIGAR_TCP_SYN_RECV;
      case TCPS_ESTABLISHED:
        return SIGAR_TCP_ESTABLISHED;
      case TCPS_CLOSE_WAIT:
        return SIGAR_TCP_CLOSE_WAIT;
      case TCPS_FIN_WAIT_1:
        return SIGAR_TCP_FIN_WAIT1;
      case TCPS_CLOSING:
        return SIGAR_TCP_CLOSING;
      case TCPS_LAST_ACK:
        return SIGAR_TCP_LAST_ACK;
      case TCPS_FIN_WAIT_2:
        return SIGAR_TCP_FIN_WAIT2;
      case TCPS_TIME_WAIT:
        return SIGAR_TCP_TIME_WAIT;
      default:
        return SIGAR_TCP_UNKNOWN;
    }
}

static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    int flags = walker->flags;
    int type, istcp = 0;
    char *buf;
    const char *mibvar;
    struct tcpcb *tp = NULL;
    struct inpcb *inp;
    struct xinpgen *xig, *oxig;
    struct xsocket *so;
    size_t len;

    switch (proto) {
      case IPPROTO_TCP:
        mibvar = "net.inet.tcp.pcblist";
        istcp = 1;
        type = SIGAR_NETCONN_TCP;
        break;
      case IPPROTO_UDP:
        mibvar = "net.inet.udp.pcblist";
        type = SIGAR_NETCONN_UDP;
        break;
      default:
        mibvar = "net.inet.raw.pcblist";
        type = SIGAR_NETCONN_RAW;
        break;
    }

    len = 0;
    if (sysctlbyname(mibvar, 0, &len, 0, 0) < 0) {
        return errno;
    }
    if ((buf = malloc(len)) == 0) {
        return errno;
    }
    if (sysctlbyname(mibvar, buf, &len, 0, 0) < 0) {
        free(buf);
        return errno;
    }

    oxig = xig = (struct xinpgen *)buf;
    for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
         xig->xig_len > sizeof(struct xinpgen);
         xig = (struct xinpgen *)((char *)xig + xig->xig_len))
    {
        if (istcp) {
            struct xtcpcb *cb = (struct xtcpcb *)xig;
            tp = &cb->xt_tp;
            inp = &cb->xt_inp;
            so = &cb->xt_socket;
        }
        else {
            struct xinpcb *cb = (struct xinpcb *)xig;
            inp = &cb->xi_inp;
            so = &cb->xi_socket;
        }

        if (so->xso_protocol != proto) {
            continue;
        }

        if (inp->inp_gencnt > oxig->xig_gen) {
            continue;
        }

        if ((((flags & SIGAR_NETCONN_SERVER) && so->so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !so->so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (inp->inp_vflag & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inp->in6p_laddr.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inp->in6p_faddr.s6_addr);
            }
            else {
                sigar_net_address_set(conn.local_address,
                                      inp->inp_laddr.s_addr);

                sigar_net_address_set(conn.remote_address,
                                      inp->inp_faddr.s_addr);
            }

            conn.local_port  = ntohs(inp->inp_lport);
            conn.remote_port = ntohs(inp->inp_fport);
            conn.receive_queue = so->so_rcv.sb_cc;
            conn.send_queue    = so->so_snd.sb_cc;
            conn.uid           = so->so_pgid;
            conn.type = type;

            if (!istcp) {
                conn.state = SIGAR_TCP_UNKNOWN;
                if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                    break;
                }
                continue;
            }

            conn.state = net_connection_state_get(tp->t_state);

            if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                break;
            }
        }
    }

    free(buf);

    return SIGAR_OK;
}

int sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    int flags = walker->flags;
    int status;

    if (flags & SIGAR_NETCONN_TCP) {
        status = net_connection_get(walker, IPPROTO_TCP);
        if (status != SIGAR_OK) {
            return status;
        }
    }
    if (flags & SIGAR_NETCONN_UDP) {
        status = net_connection_get(walker, IPPROTO_UDP);
        if (status != SIGAR_OK) {
            return status;
        }
    }

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_net_listeners_get(sigar_net_connection_walker_t *walker)
{
    int status;

    status = sigar_net_connection_walk(walker);

    if (status != SIGAR_OK) {
        return status;
    }

#if defined(DARWIN_HAS_LIBPROC_H)
    int i;
    sigar_net_connection_list_t *list = walker->data;

    sigar_pid_t pid;
    for (i = 0; i < list->number; i++) {
        status = sigar_proc_port_get(walker->sigar, walker->flags,
            list->data[i].local_port, &pid);

        if (status == SIGAR_OK) {
            list->data[i].pid = pid;
        }
    }
#endif

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_tcp_get(sigar_t *sigar,
              sigar_tcp_t *tcp)
{
    struct tcpstat mib;
    int var[4] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
    size_t len = sizeof(mib);

    if (sysctl(var, NMIB(var), &mib, &len, NULL, 0) < 0) {
        return errno;
    }

    tcp->active_opens = mib.tcps_connattempt;
    tcp->passive_opens = mib.tcps_accepts;
    tcp->attempt_fails = mib.tcps_conndrops;
    tcp->estab_resets = mib.tcps_drops;
    if (sigar_tcp_curr_estab(sigar, tcp) != SIGAR_OK) {
        tcp->curr_estab = -1;
    }
    tcp->in_segs = mib.tcps_rcvtotal;
    tcp->out_segs = mib.tcps_sndtotal - mib.tcps_sndrexmitpack;
    tcp->retrans_segs = mib.tcps_sndrexmitpack;
    tcp->in_errs =
        mib.tcps_rcvbadsum +
        mib.tcps_rcvbadoff +
        mib.tcps_rcvmemdrop +
        mib.tcps_rcvshort;
    tcp->out_rsts = -1; /* XXX mib.tcps_sndctrl - mib.tcps_closed; ? */

    return SIGAR_OK;
}

#if !TARGET_OS_IPHONE
static int get_nfsstats(struct nfsstats *stats)
{
    size_t len = sizeof(*stats);
    int mib[] = { CTL_VFS, 2, NFS_NFSSTATS };

    if (sysctl(mib, NMIB(mib), stats, &len, NULL, 0) < 0) {
        return errno;
    }
    else {
        return SIGAR_OK;
    }
}

typedef uint64_t rpc_cnt_t;

static void map_nfs_stats(sigar_nfs_v3_t *nfs, rpc_cnt_t *rpc)
{
    nfs->null = rpc[NFSPROC_NULL];
    nfs->getattr = rpc[NFSPROC_GETATTR];
    nfs->setattr = rpc[NFSPROC_SETATTR];
    nfs->lookup = rpc[NFSPROC_LOOKUP];
    nfs->access = rpc[NFSPROC_ACCESS];
    nfs->readlink = rpc[NFSPROC_READLINK];
    nfs->read = rpc[NFSPROC_READ];
    nfs->write = rpc[NFSPROC_WRITE];
    nfs->create = rpc[NFSPROC_CREATE];
    nfs->mkdir = rpc[NFSPROC_MKDIR];
    nfs->symlink = rpc[NFSPROC_SYMLINK];
    nfs->mknod = rpc[NFSPROC_MKNOD];
    nfs->remove = rpc[NFSPROC_REMOVE];
    nfs->rmdir = rpc[NFSPROC_RMDIR];
    nfs->rename = rpc[NFSPROC_RENAME];
    nfs->link = rpc[NFSPROC_LINK];
    nfs->readdir = rpc[NFSPROC_READDIR];
    nfs->readdirplus = rpc[NFSPROC_READDIRPLUS];
    nfs->fsstat = rpc[NFSPROC_FSSTAT];
    nfs->fsinfo = rpc[NFSPROC_FSINFO];
    nfs->pathconf = rpc[NFSPROC_PATHCONF];
    nfs->commit = rpc[NFSPROC_COMMIT];
}
#endif

int sigar_nfs_client_v2_get(sigar_t *sigar,
                            sigar_nfs_client_v2_t *nfs)
{
    return SIGAR_ENOTIMPL;
}

int sigar_nfs_server_v2_get(sigar_t *sigar,
                            sigar_nfs_server_v2_t *nfs)
{
    return SIGAR_ENOTIMPL;
}

int sigar_nfs_client_v3_get(sigar_t *sigar,
                            sigar_nfs_client_v3_t *nfs)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.rpccnt[0]);

    return SIGAR_OK;
#endif
}

int sigar_nfs_server_v3_get(sigar_t *sigar,
                            sigar_nfs_server_v3_t *nfs)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.srvrpccnt[0]);

    return SIGAR_OK;
#endif
}

#if !TARGET_OS_IPHONE
static char *get_hw_type(int type)
{
    switch (type) {
    case IFT_ETHER:
        return "ether";
    case IFT_ISO88025:
        return "tr";
    case IFT_FDDI:
        return "fddi";
    case IFT_ATM:
        return "atm";
    case IFT_L2VLAN:
        return "vlan";
    case IFT_IEEE1394:
        return "firewire";
#ifdef IFT_BRIDGE
    case IFT_BRIDGE:
        return "bridge";
#endif
    default:
        return "unknown";
    }
}
#endif

int sigar_arp_list_get(sigar_t *sigar,
                       sigar_arp_list_t *arplist)
{
#if TARGET_OS_IPHONE
    return SIGAR_ENOTIMPL;
#else
    size_t needed;
    char *lim, *buf, *next;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };

    if (sysctl(mib, NMIB(mib), NULL, &needed, NULL, 0) < 0) {
        return errno;
    }

    if (needed == 0) { /* empty cache */
        return 0;
    }

    buf = malloc(needed);

    if (sysctl(mib, NMIB(mib), buf, &needed, NULL, 0) < 0) {
        free(buf);
        return errno;
    }

    sigar_arp_list_create(arplist);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        sigar_arp_t *arp;

        SIGAR_ARP_LIST_GROW(arplist);
        arp = &arplist->data[arplist->number++];

        rtm = (struct rt_msghdr *)next;
        sin = (struct sockaddr_inarp *)(rtm + 1);
        sdl = (struct sockaddr_dl *)((char *)sin + SA_SIZE(sin));

        sigar_net_address_set(arp->address, sin->sin_addr.s_addr);
        sigar_net_address_mac_set(arp->hwaddr, LLADDR(sdl), sdl->sdl_alen);
        if_indextoname(sdl->sdl_index, arp->ifname);
        arp->flags = rtm->rtm_flags;

        SIGAR_SSTRCPY(arp->type, get_hw_type(sdl->sdl_type));
    }

    free(buf);

    return SIGAR_OK;
#endif
}

#if defined(DARWIN_HAS_LIBPROC_H)

int sigar_proc_port_get(sigar_t *sigar, int protocol,
                        unsigned long port, sigar_pid_t *pid)
{
    sigar_proc_list_t pids;
    int i, status, found=0;

    if (!sigar->libproc) {
        return SIGAR_ENOTIMPL;
    }

    status = sigar_proc_list_get(sigar, &pids);
    if (status != SIGAR_OK) {
        return status;
    }

    for (i=0; i<pids.number; i++) {
        int n, num=0;
        struct proc_fdinfo *fdinfo;

        status = proc_fdinfo_get(sigar, pids.data[i], &num);
        if (status != SIGAR_OK) {
            continue;
        }
        fdinfo = (struct proc_fdinfo *)sigar->ifconf_buf;

        for (n=0; n<num; n++) {
            struct proc_fdinfo *fdp = &fdinfo[n];
            struct socket_fdinfo si;
            int rsize, family;
            unsigned long lport;

            if (fdp->proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }
            rsize = sigar->proc_pidfdinfo(pids.data[i], fdp->proc_fd,
                                          PROC_PIDFDSOCKETINFO, &si, sizeof(si));
            if (rsize != sizeof(si)) {
                continue;
            }
            if (si.psi.soi_kind != SOCKINFO_TCP) {
                continue;
            }
            if (si.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) {
                continue;
            }
            family = si.psi.soi_family;
            if (!((family == AF_INET) || (family == AF_INET6))) {
                continue;
            }
            lport = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
            if (lport == port) {
                *pid = pids.data[i];
                found = 1;
                break;
            }
        }
    }

    sigar_proc_list_destroy(sigar, &pids);

    return found ? SIGAR_OK : ENOENT;
}

#endif

int sigar_os_sys_info_get(sigar_t *sigar,
                          sigar_sys_info_t *sysinfo)
{
#if TARGET_OS_IPHONE
    char osversion[32] = "Unknown";
    size_t s = sizeof(osversion);
    sysctlbyname("kern.osversion", &osversion, &s, NULL, 0);
    SIGAR_SSTRCPY(sysinfo->version, osversion);

    struct utsname uname_data;
    uname(&uname_data);
    SIGAR_SSTRCPY(sysinfo->name, "iOS");
    SIGAR_SSTRCPY(sysinfo->vendor_name, "Apple");
    SIGAR_SSTRCPY(sysinfo->vendor, "Apple");
    SIGAR_SSTRCPY(sysinfo->vendor_version, uname_data.release);
    SIGAR_SSTRCPY(sysinfo->vendor_code_name, uname_data.machine);
    SIGAR_SSTRCPY(sysinfo->description, uname_data.machine);
#else
    char *codename = NULL;
    int version_major, version_minor, version_fix;

    SIGAR_SSTRCPY(sysinfo->name, "macOS");
    SIGAR_SSTRCPY(sysinfo->vendor_name, "macOS");
    SIGAR_SSTRCPY(sysinfo->vendor, "Apple");

    FILE *fp = popen("/usr/bin/sw_vers -productVersion", "r");
    if (fp == NULL) {
        return SIGAR_ENOTIMPL;
    }
    char str[1024];
    int  count;

    char *val = fgets(str, sizeof(str) - 1, fp);
    pclose(fp);
    count = sscanf(val, "%d.%d.%d", &version_major, &version_minor, &version_fix);

    if(count < 2) {
        return SIGAR_ENOTIMPL;
    }

    snprintf(sysinfo->vendor_version,
             sizeof(sysinfo->vendor_version),
             "%d.%d",
             version_major, version_minor);

    snprintf(sysinfo->version,
             sizeof(sysinfo->version),
             "%s.%d",
             sysinfo->vendor_version, version_fix);

    if (version_major == 13) {
      codename = "Ventura";
    }
    else if (version_major == 12) {
      codename = "Monterey";
    }
    else if (version_major == 11) {
      codename = "Big Sur";
    }
    else if (version_major == 10) {
        switch (version_minor) {
          case 2:
            codename = "Jaguar";
            break;
          case 3:
            codename = "Panther";
            break;
          case 4:
            codename = "Tiger";
            break;
          case 5:
            codename = "Leopard";
            break;
          case 6:
            codename = "Snow Leopard";
            break;
          case 7:
            codename = "Lion";
            break;
          case 8:
            codename = "Mountain Lion";
            break;
          case 9:
            codename = "Mavericks";
            break;
          case 10:
            codename = "Yosemite";
            break;
          case 11:
            codename = "El Capitan";
            break;
          case 12:
            codename = "Sierra";
            break;
          case 13:
            codename = "High Sierra";
            break;
          case 14:
            codename = "Mojave";
            break;
          case 15:
            codename = "Catalina";
            break;
          default:
            codename = "Unknown";
            break;
        }
    }
    else {
        return SIGAR_ENOTIMPL;
    }

    SIGAR_SSTRCPY(sysinfo->vendor_code_name, codename);

    snprintf(sysinfo->description,
             sizeof(sysinfo->description),
             "%s %s",
             sysinfo->vendor_name, sysinfo->vendor_code_name);
#endif

    const char * arch = "unknown";
    size_t size;
    cpu_type_t type;
    cpu_subtype_t subtype;
    size = sizeof(type);
    sysctlbyname("hw.cputype", &type, &size, NULL, 0);
    size = sizeof(subtype);
    sysctlbyname("hw.cpusubtype", &subtype, &size, NULL, 0);

    if (type == CPU_TYPE_X86_64) {
        arch = "x86_64";
    } else if (type == CPU_TYPE_X86) {
        arch = "x86";
    } else if (type == CPU_TYPE_POWERPC) {
        arch = "powerpc";
    } else if (type == CPU_TYPE_POWERPC64) {
        arch = "powerpc64";
    } else if (type == CPU_TYPE_ARM) {
        switch(subtype) {
#ifdef CPU_SUBTYPE_ARM_V6
            case CPU_SUBTYPE_ARM_V6:
                arch = "armv6";
                break;
#endif
#ifdef CPU_SUBTYPE_ARM_V7
            case CPU_SUBTYPE_ARM_V7:
                arch = "armv7";
                break;
#endif
#ifdef CPU_SUBTYPE_ARM_V7S
            case CPU_SUBTYPE_ARM_V7S:
                arch = "armv7s";
                break;
#endif
#ifdef CPU_SUBTYPE_ARM_V8
            case CPU_SUBTYPE_ARM_V8:
                arch = "armv8";
                break;
#endif
            default:
                arch = "arm";
        }
#ifdef CPU_TYPE_ARM64
    } else if (type == CPU_TYPE_ARM64) {
        arch = "arm64";
#endif
    }
    SIGAR_SSTRCPY(sysinfo->arch, arch);
    return SIGAR_OK;
}

int sigar_os_is_in_container(sigar_t *sigar)
{
    return 0;
}
