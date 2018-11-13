# 1. 基本概念

## 1.1 namespaces

namespaces用于隔离一系列系统资源，当前内核共实现6种类型的namespace:

|  类型   | 系统调用参数  | kernel版本 |
| :-----: | ------------- | ---------- |
|  Mount  | CLONE_NEWNS   | 2.4.19     |
|   UTS   | CLONE_NEWUTS  | 2.6.19     |
|   IPC   | CLONE_NEWIPC  | 2.6.19     |
|   PID   | CLONE_NEWPID  | 2.6.24     |
| Network | CLONE_NEWNET  | 2.6.29     |
|  User   | CLONE_NEWUSER | 3.8        |

namespace涉及以下3个系统调用：

- clone()：根据namespace类型创建新的进程。

  ```c
             #define _GNU_SOURCE
             #include <sched.h>
  
             int clone(int (*fn)(void *), void *child_stack,
                   int flags, void *arg, ...
                   /* pid_t *ptid, void *newtls, pid_t *ctid */ );
  ```

- unshare()：将进程移出某namespace。

  ```c
  #define _GNU_SOURCE
  #include <sched.h>
  
  int unshare(int flags);
  ```

- setns()：将进程加入namespace中。

  ```c
  #define _GNU_SOURCE             /* See feature_test_macros(7) */
  #include <sched.h>
  
  int setns(int fd, int nstype);
  ```

namespace涉及命令：

**`nsenter`**  - run program with namespaces of other processes

参数如下：

```
--target pid 从指定进程获取上下文
              /proc/pid/ns/mnt    the mount namespace
              /proc/pid/ns/uts    the UTS namespace
              /proc/pid/ns/ipc    the IPC namespace
              /proc/pid/ns/net    the network namespace
              /proc/pid/ns/pid    the PID namespace
              /proc/pid/ns/user   the user namespace
              /proc/pid/ns/cgroup the cgroup namespace
              /proc/pid/root      the root directory
              /proc/pid/cwd       the working directory respectively
--mount[=file] 进入mount namespace
--uts[=file]   进入uts namespace
--ipc[=file]   进入IPC namaspace
--net[=file]   进入network namespace
--pid[=file]   进入pid namespace
--user[=file]  进入user namespace
--cgroup[=file] 进入user namespace
--root[=directory] 设置root目录
```

该命令可以用于进入docker内部：

```shell
# docker inspect -f {{.State.Pid}} tomcat
# nsenter --mount --uts --ipc --net --pid --target 31356 bash
```

**`lsns`** - list namespaces



## 1.2 cgroup

cgroup用于对进程占用的资源进行限制、监控和统计，这些资源包含CPU，内存，存储，网络等。通过Cgroup可以方便地限制某个进程的资源占用，并可以对进程实时监控和统计信息。

cgroup包含三个组件：
- cgroup：
  对进程分组管理，一个cgroup包含一组进程，可以在该cgroup上设置subsystem中的各种参数。

- subsystem：
  一组资源控制模块，关联到cgroup上并对该cgroup中的进程做限制和控制。可以通过lssubsys命令查看当前内核支持的subsystem，通常包含以下几项：
  `blkio`：  设置块设备IO访问控制 
  `cpu` ：   设置cgroup中进程的cpu调度策略
  `cpuacct`：统计cgroup中进程的cpu占用率
  `cpuset`： 多核中设置cpu中进程可以使用的cpu和内存
  `devices`  控制cgroup中进程对设备的访问
  `freezer`  suspend/resume cgrpup中的进程
  `memory`   控制cgroup中进程的内存占用
  `net_cls`  将cgroup中进程产生的网络包分类，便于TC限流
  `net_prio` 设置cgroup中进程产生的网络流量的优先级
  `hugetlb`
  `pids`

- hierarchy
  通过hierarchy将一组cgroup组成树状结构，通过树状结构实现继承。类如cgroup1限制了IO访问，其中某个进程需要进一步限制设备访问，为了避免影响cgroup1中其他进程，可以创建cgroup2，继承cgroup1的限制，并增加设备访问限制而不影响cgroup1中的其他进程。

cgconfigparser - setup control group file system

/usr/bin/cgclassify
/usr/bin/cgcreate
/usr/bin/cgdelete
/usr/bin/cgexec
/usr/bin/cgget
/usr/bin/cgset
/usr/bin/cgsnapshot
/usr/bin/lscgroup
/usr/bin/lssubsys

/usr/sbin/cgclear
/usr/sbin/cgconfigparser

## 1.3 capabilities

### 1.3.1 介绍

linux系统上，为了限制进程的权限，把进程分为特权进程(UID为0)和非特权进程(UID非0)，特权进程可以通过年和所有权限检查，非特权进程则基于UID/GID。内核从2.1版本引入capability概念，把超级用户不同单元的权限分开，可以单独的开启和禁止，以将能力赋给普通的进程，普通用户也可以做只有root用户可以完成的工作.

#### 1.3.1.1 进程capability集

每个进程有5个和capability有关的位图：Permitted，Inheritable，Effective，Ambient, Bset。对应进程描述符task_struct中的cred(include/linux/cred.h)里面的cap_permitted，cap_inheritable, cap_effective, cap_ambient，cap_bset 。

- Permitted
  表示进程能够使用的capability，在cap_permitted中可以包含cap_effective中没有的capability，这些capability是被进程自己临时放弃的，也可以说cap_effective是cap_permitted的一个子集.
- Inheritable
  表示子进程能够继承的capability。
- Effective
  当一个进程要进行某个特权操作时，内核会检查cap_effective的对应位是否有效，而不再是检查进程的UID是否为0.
- Ambient
- Bset

#### 1.3.1.2 文件capabilities

从2.6.24开始，Linux内核可以给可执行文件赋予能力，可执行文件包含三个能力集：

- Permitted

  该能力当可执行文件执行时自动附加到进程中，忽略Inhertiable capability。

- Inheritable

  它与进程的Inheritable集合做与操作，决定执行execve后新进程的Permitted集合。

- Effective

  文件的Effective不是一个集合，而是一个单独的位，用来决定进程成的Effective集合。

### 1.3.2 Capabilities list
当前Linux系统中共有38项特权，可在include/uapi/linux/capability.h文件中查看定义，进程的能力可以通过/proc/PID/status来查看。

```
CAP_CHOWN                0 - 允许改变文件的所有权
CAP_DAC_OVERRIDE         1 - 忽略对文件的所有DAC访问限制
CAP_DAC_READ_SEARCH      2 - 忽略所有对读、搜索操作的限制
CAP_FOWNER               3 - 以最后操作的UID,覆盖文件的先前的UID
CAP_FSETID               4 - 确保在文件被修改后不修改setuid/setgid位
CAP_KILL                 5 - 允许对不属于自己的进程发送信号
CAP_SETGID               6 - 设定程序允许普通用户使用setgid函数,这与文件的setgid权限位无关
CAP_SETUID               7 - 设定程序允许普通用户使用setuid函数,这也文件的setuid权限位无关
CAP_SETPCAP              8 - 允许向其它进程转移能力以及删除其它进程的任意能力
CAP_LINUX_IMMUTABLE      9 - 允许修改文件的不可修改(IMMUTABLE)和只添加(APPEND-ONLY)属性
CAP_NET_BIND_SERVICE     10 - 允许绑定到小于1024的端口
CAP_NET_BROADCAST        11 - 允许网络广播和多播访问
CAP_NET_ADMIN            12 - 允许执行网络管理任务:接口,防火墙和路由等
CAP_NET_RAW              13 - 允许使用原始(raw)套接字
CAP_IPC_LOCK             14 - 允许锁定内存片段
CAP_IPC_OWNER            15 - 忽略IPC所有权检查
CAP_SYS_MODULE           16 - 允许普通用户插入和删除内核模块
CAP_SYS_RAWIO            17 - 允许用户打开端口,并读取修改端口数据,一般用ioperm/iopl函数
CAP_SYS_CHROOT           18 - 允许使用chroot()系统调用
CAP_SYS_PTRACE           19 - 允许跟踪任何进程
CAP_SYS_PACCT            20 - 允许配置process accounting
CAP_SYS_ADMIN            21 - 允许执行系统管理任务,如挂载/卸载文件系统等
CAP_SYS_BOOT             22 - 允许普通用使用reboot()函数
CAP_SYS_NICE             23 - 允许提升优先级,设置其它进程的优先级
CAP_SYS_RESOURCE         24 - 忽略资源限制
CAP_SYS_TIME             25 - 允许改变系统时钟
CAP_SYS_TTY_CONFIG       26 - 允许配置TTY设备
CAP_MKNOD                27 - 允许使用mknod系统调用
CAP_LEASE                28 - 允许在文件上建立租借锁
CAP_SETFCAP              31 - 允许在指定的程序上授权能力给其它程序
CAP_WAKE_ALARM
CAP_BLOCK_SUSPEND
CAP_SYSLOG
CAP_MAC_ADMIN
CAP_MAC_OVERRIDE
CAP_AUDIT_CONTROL
CAP_AUDIT_READ
CAP_AUDIT_WRITE               以上6个涉及syslog,mac,audit等安全模块安全模块
```

> 参考：https://www.cnblogs.com/iamfy/archive/2012/09/20/2694977.html

### 1.3.3 libcap

capsh      - capability shell wrapper
getcap      - 获取可执行文件所具有的能力
setcap       - 设置可执行文件的能力
getpcaps  - 获取进程的能力
使用示例：
授权普通用户可以用/bin/chown程序更改任意文件的owner

```bash
# setcap cap_chown=eip /bin/chown // 将chown的能力以e,i,p三种位图授权给可执行文件
# getcap /bin/chown               // 查看可执行文件cap
/bin/chown = cap_chown+eip
# setcap -r /bin/chown            // 删除cap
```

### 1.3.4 golibcap

https://github.com/syndtr/gocapability



## 1.4 seccomp

###  14.1 介绍

Linux kernel 从2.6.23版本引入的一种简洁的 sandboxing 机制。

内核中的系统调用直接暴露给用户态程序，但是用户态程序并不需要所有的系统调用，而且不安全的代码滥用系统调用会对系统造成安全威胁。通过seccomp(secure computing mode)可以限制进程使用某些系统调用，每个进程进行系统调用时，kernal 都会检查对应的白名单以确认该进程是否有权限使用这个系统调用。白名单是用 berkeley package filter（BPF）格式书写。

### 1.4.2 使用seccomp

内核配置中开启了CONFIG_SECCOMP和CONFIG_SECCOMP_FILTER后，通过系统调用[ptrctl(2)](http://www.kernel.org/doc/man-pages/online/pages/man2/prctl.2.html)或者通过系统调用[seccomp(2)](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)开启seccomp。

seccomp - operate on Secure Computing state of the process

```c
       #include <linux/seccomp.h>
       #include <linux/filter.h>
       #include <linux/audit.h>
       #include <linux/signal.h>
       #include <sys/ptrace.h>

       int seccomp(unsigned int operation, unsigned int flags, void *args);
```

当前支持以下falgs：

```
SECCOMP_SET_MODE_STRICT
SECCOMP_SET_MODE_FILTER
SECCOMP_GET_ACTION_AVAIL
```

prctl - operations on a process

```c
 #include <sys/prctl.h>

int prctl(int option, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4, unsigned long arg5);
```

### 1.4.3 seccomp模式

seccomp支持两种模式：

- **SECCOMP_MODE_STRICT**

  在SECCOMP_MODE_STRICT模式下，进程不能使用read(2)，write(2)，_exit(2)和sigreturn(2)以外的其他系统调用。

- **SECCOMP_MODE_FILTER**

  在SECCOMP_MODE_FILTER模式下，可以利用Berkeley Packet Filter配置哪些系统调用及它们的参数可以被进程使用。

> https://blog.csdn.net/chweiweich/article/details/55098410

### 1.4.4 Filters

SECCOMP_SET_MODE_FILTER模式中args为指向sock_fprog的指针

```c
           struct sock_fprog {
               unsigned short      len;    /* Number of BPF instructions */
               struct sock_filter *filter; /* Pointer to array of
                                              BPF instructions */
           };
```

包含一个或多个BPF指令

```c
           struct sock_filter {            /* Filter block */
               __u16 code;                 /* Actual filter code */
               __u8  jt;                   /* Jump true */
               __u8  jf;                   /* Jump false */
               __u32 k;                    /* Generic multiuse field */
           };
```

使用示例：

```c
       #include <errno.h>
       #include <stddef.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <unistd.h>
       #include <linux/audit.h>
       #include <linux/filter.h>
       #include <linux/seccomp.h>
       #include <sys/prctl.h>

       #define X32_SYSCALL_BIT 0x40000000

       static int
       install_filter(int syscall_nr, int t_arch, int f_errno)
       {
           unsigned int upper_nr_limit = 0xffffffff;

           /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI */
           if (t_arch == AUDIT_ARCH_X86_64)
               upper_nr_limit = X32_SYSCALL_BIT - 1;

           struct sock_filter filter[] = {
               /* [0] Load architecture from 'seccomp_data' buffer into
                      accumulator */
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        (offsetof(struct seccomp_data, arch))),

               /* [1] Jump forward 5 instructions if architecture does not
                      match 't_arch' */
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_arch, 0, 5),

               /* [2] Load system call number from 'seccomp_data' buffer into
                      accumulator */
               BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                        (offsetof(struct seccomp_data, nr))),

               /* [3] Check ABI - only needed for x86-64 in blacklist use
                      cases.  Use JGT instead of checking against the bit
                      mask to avoid having to reload the syscall number. */
               BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 3, 0),

               /* [4] Jump forward 1 instruction if system call number
                      does not match 'syscall_nr' */
               BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1),
               /* [5] Matching architecture and system call: don't execute
                   the system call, and return 'f_errno' in 'errno' */
               BPF_STMT(BPF_RET | BPF_K,
                        SECCOMP_RET_ERRNO | (f_errno & SECCOMP_RET_DATA)),

               /* [6] Destination of system call number mismatch: allow other
                      system calls */
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

               /* [7] Destination of architecture mismatch: kill process */
               BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
           };

           struct sock_fprog prog = {
               .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
               .filter = filter,
           };

           if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)) {
               perror("seccomp");
               return 1;
           }

           return 0;
       }

       int
       main(int argc, char **argv)
       {
           if (argc < 5) {
               fprintf(stderr, "Usage: "
                       "%s <syscall_nr> <arch> <errno> <prog> [<args>]\n"
                       "Hint for <arch>: AUDIT_ARCH_I386: 0x%X\n"
                       "                 AUDIT_ARCH_X86_64: 0x%X\n"
                       "\n", argv[0], AUDIT_ARCH_I386, AUDIT_ARCH_X86_64);
               exit(EXIT_FAILURE);
           }

           if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
               perror("prctl");
               exit(EXIT_FAILURE);
           }

           if (install_filter(strtol(argv[1], NULL, 0),
                              strtol(argv[2], NULL, 0),
                              strtol(argv[3], NULL, 0)))
               exit(EXIT_FAILURE)
           execv(argv[4], &argv[4]);
           perror("execv");
           exit(EXIT_FAILURE);
       }
```

### 1.4.5golibseccomp

https://github.com/seccomp/libseccomp-golang

## 1.5 rlimits

获取/设置进程的资源限制，包含以下系统调用，可以通过`/proc/pid/limts`查看

```c
       #include <sys/time.h>
       #include <sys/resource.h>

       int getrlimit(int resource, struct rlimit *rlim);
       int setrlimit(int resource, const struct rlimit *rlim);

       int prlimit(pid_t pid, int resource, const struct rlimit *new_limit,
                   struct rlimit *old_limit);
```

resource参数可以指定如下

```
RLIMIT_AS     - 限制进程vm
RLIMIT_CORE   - 限制进程corefile大小
RLIMIT_CPU    - 限制进程cpu
RLIMIT_DATA   - 限制进程数据段大小(initialized data, uninitialized data, and heap)
RLIMIT_FSIZE  - 限制进程创建文件大小
RLIMIT_LOCKS  
RLIMIT_MEMLOCK
RLIMIT_MSGQUEUE
RLIMIT_NICE
RLIMIT_NOFILE
RLIMIT_NPROC
RLIMIT_RSS
RLIMIT_RTPRIO
RLIMIT_RTTIME
RLIMIT_SIGPENDING
RLIMIT_STACK
```



##1.6 UFS



# 2. OCI

## 2.1 OCI标准

Linux基金会于2015年6月成立OCI（Open Container Initiative）组织，旨在围绕容器**runtime**和**image**制定一个开放的工业化标准。该组织一成立便得到了包括谷歌、微软、亚马逊、华为等一系列云计算厂商的支持。目前OCI发布了两个规范：**runtime-spec**，**image-spec**。而runC就是由Docker贡献、按照该开放容器格式标准（OCF, Open Container Format）制定的一种具体实现。

当前，采用OCI runtime规范的项目如下：
- **Runtime (Container)**
  - [opencontainers/runc](https://github.com/opencontainers/runc) - Reference implementation of OCI runtime
  - [projectatomic/bwrap-oci](https://github.com/projectatomic/bwrap-oci) - Convert the OCI spec file to a command line for --[bubblewrap](https://github.com/projectatomic/bubblewrap)
  - [giuseppe/crun](https://github.com/giuseppe/crun) - Runtime implementation in C

- **Runtime (Virtual Machine)**
  - [hyperhq/runv](https://github.com/hyperhq/runv) - Hypervisor-based runtime for OCI
  - [clearcontainers/runtime](https://github.com/clearcontainers/runtime)- Hypervisor-based OCI runtime utilising [virtcontainers][virtcontainers] by Intel®.

当前，采用OCI image规范的项目如下：

- [projectatomic/skopeo](https://github.com/projectatomic/skopeo)
- [Amazon Elastic Container Registry (ECR)](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-manifest-formats.html) ([announcement](https://aws.amazon.com/about-aws/whats-new/2017/01/amazon-ecr-supports-docker-image-manifest-v2-schema-2/))
- [openSUSE/umoci](https://github.com/openSUSE/umoci)
- [cloudfoundry/grootfs](https://github.com/cloudfoundry/grootfs) ([source](https://github.com/cloudfoundry/grootfs/blob/c3da26e1e463b51be1add289032f3dca6698b335/fetcher/remote/docker_src.go))
- [Mesos plans](https://issues.apache.org/jira/browse/MESOS-5011) ([design doc](https://docs.google.com/document/d/1Pus7D-inIBoLSIPyu3rl_apxvUhtp3rp0_b0Ttr2Xww/edit#heading=h.hrvk2wboog4p))
- [Docker](https://github.com/docker)
  - [docker/docker (`docker save/load` WIP)](https://github.com/docker/docker/pull/26369)
  - [docker/distribution (registry PR)](https://github.com/docker/distribution/pull/2076)
- [containerd/containerd](https://github.com/containerd/containerd)
- [Containers](https://github.com/containers/)
  - [containers/build](https://github.com/containers/build)
  - [containers/image](https://github.com/containers/image)
- [coreos/rkt](https://github.com/coreos/rkt)
- [box-builder/box](https://github.com/box-builder/box)
- [coolljt0725/docker2oci](https://github.com/coolljt0725/docker2oci)

## 2.2 bundle

OCI标准包(bundle)用于将容器及容器的配置数据存储在磁盘上以便运行时读取，包含以下两个部分：

### 2.2.1 config.json

容器配置数据，config.json可以通过`runc spec `命令生成。包含容器运行的进程，与宿主机独立的和应用相关的特定信息，如安全权限、环境变量和参数等。具体如下：

- ociVersion - OCI规范的版本

- root - 容器的rootfs

  ```json
          "root": {
                  "path": "rootfs",  //rootfs路径
                  "readonly": true   //rootfs是否只读
          },
  ```

- hostname - 配置容器hostname，只有创建了UTS NS才可以指定

- process - 容器的进程信息

  - terminal - 指定是否连接终端。

  - user - 指定容器中进程的UID/GID

  - args - 传递给可执行文件的参数

  - cwd - 可执行文件的工作目录，必须是绝对路径。

  - env - 传递给进程的环境变量，为key=value格式。

  - **capabilities** - 指定容器中进程的capabilities

    - bounding
    - effective
    - inheritable
    - permitted
    - ambient

  - **rlimits** - 设置容器中进程的资源限额
    - type - linux平台参考`man getrlimit`，例如RLIMIT_MSGQUEUE
    - soft
    - hard 
    ```json
                    "rlimits": [
                            {
                                    "type": "RLIMIT_NOFILE",
                                    "hard": 1024,
                                    "soft": 1024
                            }
                    ]
    ```

  - noNewPrivileges - 是否以特权运行

- mounts - 配置容器中的挂载点通常容器包含以下挂载点(/proc, /dev, /dev/pts, /dev/shm, /dev/mqueue,/sys  , /sys/fs/cgroup等)
  - destination - 挂载点在容器内的目标位置
  - type             - 文件系统类型
  - source         - 源设备名或文件名
  - options       - 挂载参数

- linux  - 平台相关的配置(linux, win, vm等)，
  - cgroupPath - 设置cgroup路径

  - **resources**  - 设置cgroup资源限额
    - network - net_cls，net_prio限额
      ```json
          "network": {
              "classID": 1048577,
              "priorities": [
                  {
                      "name": "eth0",
                      "priority": 500
                  },
              ]
         }
      ```

    - pids

    - memory - 设置内存限额

      ```json
          "memory": {                   
              "limit": 536870912,         # 限额
              "reservation": 536870912,   # 软限额
              "swap": 536870912,          # memory+swap 限额
              "kernel": -1,               # 内核memory hard限额
              "kernelTCP": -1,            # 内核TCP buffer memory hard限额
              "swappiness": 0,
              "disableOOMKiller": false
          }
      ```

    - cpu

      ```json
                  "cpu": {
                      "shares": 1024,     # 指定cgroup中任务可用的CPU时间的相对份额
                      "quota": 1000000,   # 指定任务在时间段内可以运行的总时间
                      "period": 500000,  # 指定定期重新分配对CPU资源的访问权限的时间段
                      "realtimeRuntime": 950000,
                      "realtimePeriod": 1000000,
                      "cpus": "2-3",      # 列出container可用的cpu
                      "mems": "0-7"
                  },
      ```

    - blockIO

      ```json
                  "blockIO": {
                      "weight": 10,      # 指定每个cgroup的权重。 
                      "leafWeight": 10,  
                      "weightDevice": [  # 设备权重
                          {
                              "major": 8,
                              "minor": 0,
                              "weight": 500,
                              "leafWeight": 300
                          },
                          {
                              "major": 8,
                              "minor": 16,
                              "weight": 500
                          }
                      ],
                      "throttleReadBpsDevice": [  # bandwidth rate limits
                          {
                              "major": 8,
                              "minor": 0,
                              "rate": 600
                          }
                      ],
                      "throttleWriteIOPSDevice": [ # IO rate limits
                          {
                              "major": 8,
                              "minor": 16,
                              "rate": 300
                          }
                      ]
                  }
      ```

    - device - 设置Device白名单访问权限

      ```json
          "devices": [
              {
                  "allow": false,
                  "access": "rwm"
              },
              {
                  "allow": true,
                  "type": "c",
                  "major": 10,
                  "minor": 229,
                  "access": "rw"
              },
              {
                  "allow": true,
                  "type": "b",
                  "major": 8,
                  "minor": 0,
                  "access": "r"
              }
          ]

      ```

    - hugepageLimits - HugeTLB限额

    - rdma

    - intelRdt

  - namespaces  - 设置容器的namespace，可以指定type(pid,network,mount等)和path两个参数

  - **seccomp** - 限制容器的系统调用

    - defaultAction   - seccomp 默认action

    - architectures    - 系统架构(SCMP_ARCH_X86,SCMP_ARCH_X86_64...)

    - syscalls  - 限制系统调用及其参数

      ```json
              "syscalls": [
                  {
                      "names": [
                          "clone",
                      ],
                      "action": "SCMP_ACT_ALLOW"
                      "args": [
                      	{
                      		"index": 0,
                      		"value": 2080505856,
                      		"op": "SCMP_CMP_MASKED_EQ"
                  		}
                  }
              ]
      ```



  - devices  - 列出容器中可用的devices

    ```json
            "devices": [
                {
                    "path": "/dev/sda",
                    "type": "b",
                    "major": 8,
                    "minor": 0,
                    "fileMode": 432,
                    "uid": 0,
                    "gid": 0
                }
            ],
    ```

  - sysctl  - 允许容器修改内核参数

    ```json
           "sysctl": {
                "net.ipv4.ip_forward": "1",
                "net.core.somaxconn": "256"
            },
    ```

  - maskedPaths   - 将覆盖容器内提供的路径，以便无法读取该路径。

  - readonlyPaths  - 将提供的路径设置为容器内的只读路径。

  - uidMappings/gidMappings - 设置host到container的uid/gid映射

    - containerID - 容器中的uid/gid
    - hostId           - host中被映射的uid/gid
    - size               - id size

  - rootfsPropagation - 设置rootfs mount propagation类型(shared, private, slave, unbindable)

  - mountLabel - 设置容器中mount的selinux标签

- hook - 在容器运行前和停止后执行一些命令，通常用于配置网络，volume清理等。

  - prestart - 容器创建后运行前执行
  - poststart - 容器运行后执行
  - poststop - 容器停止后执行

  ```json
      "hooks": {
          "prestart": [
              {
                  "path": "/usr/bin/fix-mounts",
                  "args": ["fix-mounts", "arg1", "arg2"],
                  "env":  [ "key1=value1"]
              },
              {
                  "path": "/usr/bin/setup-network"
              }
          ],
          "poststart": [
              {
                  "path": "/usr/bin/notify-start",
                  "timeout": 5
              }
          ],
          "poststop": [
              {
                  "path": "/usr/sbin/cleanup.sh",
                  "args": ["cleanup.sh", "-f"]
              }
          ]
      }
  ```


### 2.2.2 rootfs

根文件系统目录，包含了容器执行所需的必要环境依赖，如/bin、/var、/lib、/dev、/usr等目录及相应文件。rootfs目录必须与包含配置信息的config.json文件同时存在容器目录最顶层。



## 2.3 image-spec



# 3. runc

OCI定义了容器运行时标准，runc是从libcontainer中迁移而来，按照开放容器格式标准（OCF, Open Container Format）一种具体实现，去除了Docker包含的诸如镜像、Volume等高级特性，通过调用libcontainer包对namespaces、cgroups、capabilities以及文件系统的管理和分配实现进程资源的隔离。实现容器启停、资源隔离等功能。

## 3.1 创建容器

OCF标准中定义了关于容器conf.json和rootfs，runc就是通过这些来创建并启动一个容器.

createContainer()将config.json中的信息传递给factory的create方法，factory可以基于linux,win等系统实现，接口定义如下：

```go
type Factory interface {
        Create(id string, config *configs.Config) (Container, error)
        Load(id string) (Container, error)
        StartInitialization() error
        Type() string
}
```

Create方法检查容器的配置，初始化容器的rootfs，最后返回linuxContainer结构

```go
type linuxContainer struct {
        id                   string
        root                 string
        config               *configs.Config
        cgroupManager        cgroups.Manager
        intelRdtManager      intelrdt.Manager
        initPath             string
        initArgs             []string
        initProcess          parentProcess
        initProcessStartTime uint64
        criuPath             string
        newuidmapPath        string
        newgidmapPath        string
        m                    sync.Mutex
        criuVersion          int  
        state                containerState
        created              time.Time
}

```





