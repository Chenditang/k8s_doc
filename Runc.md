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

每个进程有5个和capability有关的位图：Permitted，Inheritable，Effective，Ambient, B。对应进程描述符task_struct中的cred(include/linux/cred.h)里面的cap_permitted，cap_inheritable, cap_effective, cap_ambient，cap_bset 。

- Permitted
  表示进程能够使用的capability，在cap_permitted中可以包含cap_effective中没有的capability，这些capability是被进程自己临时放弃的，也可以说cap_effective是cap_permitted的一个子集.
- Inheritable
  表示子进程能够继承的capability。
- Effective
  当一个进程要进行某个特权操作时，内核会检查cap_effective的对应位是否有效，而不再是检查进程的UID是否为0.
- Ambient
- B

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
CAP_CHOWN                          0 - 允许改变文件的所有权
CAP_DAC_OVERRIDE             1 - 忽略对文件的所有DAC访问限制
CAP_DAC_READ_SEARCH      2 - 忽略所有对读、搜索操作的限制
CAP_FOWNER                         3 - 以最后操作的UID,覆盖文件的先前的UID
CAP_FSETID                             4 - 确保在文件被修改后不修改setuid/setgid位
CAP_KILL                                  5 - 允许对不属于自己的进程发送信号
CAP_SETGID                             6 - 设定程序允许普通用户使用setgid函数,这与文件的setgid权限位无关
CAP_SETUID                             7 - 设定程序允许普通用户使用setuid函数,这也文件的setuid权限位无关
CAP_SETPCAP                          8 - 允许向其它进程转移能力以及删除其它进程的任意能力
CAP_LINUX_IMMUTABLE       9 - 允许修改文件的不可修改(IMMUTABLE)和只添加(APPEND-ONLY)属性
CAP_NET_BIND_SERVICE     10 - 允许绑定到小于1024的端口
CAP_NET_BROADCAST         11 - 允许网络广播和多播访问
CAP_NET_ADMIN                  12 - 允许执行网络管理任务:接口,防火墙和路由等
CAP_NET_RAW                      13 - 允许使用原始(raw)套接字
CAP_IPC_LOCK                      14 - 允许锁定内存片段
CAP_IPC_OWNER                  15 - 忽略IPC所有权检查
CAP_SYS_MODULE               16 - 允许普通用户插入和删除内核模块
CAP_SYS_RAWIO                   17 - 允许用户打开端口,并读取修改端口数据,一般用ioperm/iopl函数
CAP_SYS_CHROOT                18 - 允许使用chroot()系统调用
CAP_SYS_PTRACE                  19 - 允许跟踪任何进程
CAP_SYS_PACCT                     20 - 允许配置process accounting
CAP_SYS_ADMIN                    21 - 允许执行系统管理任务,如挂载/卸载文件系统等
CAP_SYS_BOOT                      22 - 允许普通用使用reboot()函数
CAP_SYS_NICE                        23 - 允许提升优先级,设置其它进程的优先级
CAP_SYS_RESOURCE             24 - 忽略资源限制
CAP_SYS_TIME                       25 - 允许改变系统时钟
CAP_SYS_TTY_CONFIG          26 - 允许配置TTY设备
CAP_MKNOD                          27 - 允许使用mknod系统调用
CAP_LEASE                              28 - 允许在文件上建立租借锁
CAP_SETFCAP                         31 - 允许在指定的程序上授权能力给其它程序
CAP_WAKE_ALARM
CAP_BLOCK_SUSPEND

CAP_SYSLOG
CAP_MAC_ADMIN
CAP_MAC_OVERRIDE
CAP_AUDIT_CONTROL
CAP_AUDIT_READ
CAP_AUDIT_WRITE               以上6个涉及syslog,mac,audit等安全模块安全模块

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

## 1.5 UFS



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

- config.json

  容器配置数据，config.json可以通过`runc spec `命令生成。包含容器运行的进程，与宿主机独立的和应用相关的特定信息，如安全权限、环境变量和参数等。具体如下：

  - ociVersion - OCI规范的版本

  - root - 容器的rootfs

    ```json
            "root": {
                    "path": "rootfs",  //rootfs路径
                    "readonly": true   //rootfs是否只读
            },
    ```

  - process - 容器的进程信息

    - terminal - 指定是否连接终端。
    - user - 指定容器中进程的UID/GID
    - cwd - 可执行文件的工作目录，必须是绝对路径。
    - env - 传递给进程的环境变量，为key=value格式。
    - args - 传递给可执行文件的参数
    - capabilities - 指定容器中进程的capabilities
    - rlimits - 限制容器中进程的资源
    - noNewPrivileges - 是否以特权运行

  - mounts

  - 

- rootfs

  根文件系统目录，包含了容器执行所需的必要环境依赖，如/bin、/var、/lib、/dev、/usr等目录及相应文件。rootfs目录必须与包含配置信息的config.json文件同时存在容器目录最顶层。


# 3. runc

OCI定义了容器运行时标准，runC是从Docker的libcontainer中迁移而来，按照开放容器格式标准（OCF, Open Container Format）制定的一种具体实现，实现容器启停、资源隔离等功能。

#### 5.3 容器运行状态

容器标准格式也要求容器把自身运行时的状态持久化到磁盘中，便于外部的工具对此信息使用和演绎。运行时状态以JSON格式编码存储。推荐把运行时状态的JSON文件存储在临时文件系统中以便系统重启后会自动移除。

基于Linux内核的操作系统，该信息统一地存储在/run/opencontainer/containers目录，该目录结构下以容器ID命名的文件夹（/run/opencontainer/containers/<containerID>/state.json）中存放容器的状态信息并实时更新。有了这样默认的容器状态信息存储位置以后，外部的应用程序就可以在系统上简便地找到所有运行着的容器了。

state.json文件中包含的具体信息需要有：

- 版本信息：存放OCI标准的具体版本号。
- 容器ID：通常是一个哈希值，也可以是一个易读的字符串。在state.json文件中加入容器ID是为了便于之前提到的运行时hooks只需载入state.json就可以定位到容器，然后检测state.json，发现文件不见了就认为容器关停，再执行相应预定义的脚本操作。
- PID：容器中运行的首个进程在宿主机上的进程号。
- 容器文件目录：存放容器rootfs及相应配置的目录。外部程序只需读取state.json就可以定位到宿主机上的容器文件目录。 标准的容器生命周期应该包含三个基本过程。
- 容器创建：创建包括文件系统、namespaces、cgroups、用户权限在内的各项内容。
- 容器进程的启动：运行容器进程，进程的可执行文件定义在的config.json中，args项。
- 容器暂停：容器实际上作为进程可以被外部程序关停（kill），然后容器标准规范应该包含对容器暂停信号的捕获，并做相应资源回收的处理，避免孤儿进程的出现。

#### 5.5 runC工作原理

runC去除了Docker包含的诸如镜像、Volume等高级特性，通过调用libcontainer包对namespaces、cgroups、capabilities以及文件系统的管理和分配实现进程资源的隔离。和libcontainer相比，主要有如下变化：

1. 将`nsinit`放到外面，重命名为`runc`，使用[`cli.go`](https://github.com/codegangsta/cli)实现。
2. 按照OCF标准把原先所有信息混在一起的配置文件拆分成`config.json`和`runtime.json`。
3. 按照OCF标准增加了容器运行前和停止后执行`hook`脚本功能。
4. 增加了`runc kill`命令，用于发送一个`SIG_KILL`信号给指定容器ID的`init`进程。

##### 5.5.1 runC启动容器

OCF标准中定义了关于容器的两份配置文件和一个依赖包，runc就是通过这些来启动一个容器：

<==待补充==>

- 容器定义工具

  docker image是docker容器的模板，runtime依据docker image创建容器。dockerfile是包含若干命令的文本文件，可以通过这些命令创建出dokcer image。

- Registry

  容器是通过image创建的，需要一个仓库来统一存放image，这个仓库叫做Registry。企业可以通过Docker Registry构建私有的Registry。