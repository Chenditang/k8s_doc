#1.  crio配置

## 1.1 配置

```shell
.
├── crictl
├── crio
├── runc
├── etc
│   ├── crictl.yaml
│   ├── crio
│   │   ├── crio.conf
│   │   └── seccomp.json
│   ├── sysconfig
│   │   ├── crio-network
│   │   └── crio-storage
│   ├── systemd
│   │   └── system
│   │       ├── crio.service
│   │       └── crio-shutdown.service
│   ├── cni
│   │   └── net.d
│   │       ├── 10-crio-bridge.conf
│   │       └── 99-loopback.conf
│   └── containers
│       ├── policy.json
│       ├── registries.d
│       │   └── default.yaml
│       └── storage.conf
├── usr
│   ├── libexec
│   │   ├── cni
│   │   │   ├── bridge
│   │   │   ├── dhcp
│   │   │   ├── flannel
│   │   │   ├── host-local
│   │   │   ├── ipvlan
│   │   │   ├── loopback
│   │   │   ├── macvlan
│   │   │   ├── portmap
│   │   │   ├── tuning
│   │   │   └── vlan
│   │   └── crio
│   │       ├── conmon
│   │       └── pause
│   └── share
│       └── oci-umount
│           └── oci-umount.d
│               └── crio-umount.conf
└── var
    └── lib
        └── containers
```

上述配置涉及以下软件包：

**`cri-tools.x86_64 `**   : CLI and validation tools for Container Runtime Interface
`conmon.x86_64  `         : OCI container runtime monitor
                                       \\_/usr/libexec/crio/conmon

`cri-o.x86_64`     : Kubernetes Container Runtime Interface for OCI-based containers
                                \\_ /etc/cni/net.d/100-crio-bridge.conf
                                    /etc/cni/net.d/200-loopback.conf

​                                    /etc/crictl.yaml
                                    /etc/crio/crio.conf
                                    /etc/crio/seccomp.json

​                                    /etc/sysconfig/crio-network
                                    /etc/sysconfig/crio-storage

​                                    /usr/lib/systemd/system/cri-o.service
                                    /usr/lib/systemd/system/crio-shutdown.service
                                    /usr/lib/systemd/system/crio.service

​                                    /usr/libexec/crio/pause
                                    /usr/bin/crio

​                                    /usr/share/oci-umount/oci-umount.d/crio-umount.conf
                                    /var/lib/containers


`skopeo-containers.x86_64` : Configuration files for working with image signatures
                                                     \\_/etc/containers/policy.json
                                                        /etc/containers/registries.d/default.yaml
                                                        /etc/containers/storage.conf
                                                        /usr/share/containers/mounts.conf

`containernetworking-cni.x86_64 `: Libraries for writing CNI plugin
                                                                 \\_/usr/libexec/cni/bridge
                                                                    /usr/libexec/cni/dhcp
                                                                    /usr/libexec/cni/flannel
                                                                    /usr/libexec/cni/host-local
                                                                    /usr/libexec/cni/ipvlan
                                                                    /usr/libexec/cni/loopback
                                                                    /usr/libexec/cni/macvlan
                                                                    /usr/libexec/cni/portmap
                                                                    /usr/libexec/cni/ptp
                                                                    /usr/libexec/cni/sample
                                                                    /usr/libexec/cni/tuning
                                                                    /usr/libexec/cni/vlan


`runc.x86_64` : CLI for running Open Containers
                          \\_/usr/bin/runc


`libnet.x86_64` : C library for portable packet creation and injection

`crit.x86_64` : CRIU image tool
`criu.x86_64` : Tool for Checkpoint/Restore in User-space

`oci-umount.x86_64` : OCI umount hook for docker
`oci-systemd-hook.x86_64 `: OCI systemd hook for docker
`oci-register-machine.x86_64 `: Golang binary to register OCI containers with systemd-machined
`ocitools.x86_64 `: Collection of tools for working with the OCI runtime specification



##  1.2 crictl命令

crio守护进程旨在为Kubernetes提供[CRI](https://github.com/kubernetes/community/blob/master/contributors/devel/container-runtime-interface.md) socket接口，用于实现container的管理。

crictl命令行是一个客户端，用于与crio守护进程通信。和kubernetes守护程序连接到同一个grpc socket。类似的工具还有[`podman`](https://github.com/projectatomic/libpod) 和 [`buildah`](https://github.com/projectatomic/buildah)。

```
[container]     
    create        Create a new container
    start         Start one or more created containers
    ps            List containers
    attach        Attach to a running container
    exec          Run a command in a running container
    update        Update one or more running containers
    inspect       Display the status of one or more containers
    logs          Fetch the logs of a container
    stop          Stop one or more running containers
    rm            Remove one or more containers
[image]
     images        List images
     pull          Pull an image from a registry
     inspecti      Return the status of one ore more images
     rmi           Remove one or more images
[pod]
     runp          Run a new pod
     pods          List pods
     port-forward  Forward local port to a pod
     inspectp      Display the status of one or more pods
     stopp         Stop one or more running pods
     rmp           Remove one or more pods
[runtime]
     info          Display information of the container runtime
     version       Display runtime version information
[other]
     config        Get and set crictl options
     stats         List container(s) resource usage statistics
     completion    Output bash shell completion code
     help, h       Shows a list of commands or help for one command

```



## 1.3 创建Pod

- create pod sandbox
  ```shell
  # crictl runp sandbox_config.json
  ```

- pull image
  ```
  # crictl pull quay.io/crio/redis:alpine
  ```

- create a redis container from a container configuration and attach it to the Pod created earlier
  ```shell
  # crictl create 9b60a39cf9141 container_redis.json sandbox_config.json
  ```

- Connect to the Pod IP on port 6379
  ```
  # telnet 10.88.0.3 6379
  Trying 10.88.0.3...
  Connected to 10.88.0.3.
  Escape character is '^]'.
  MONITOR
  +OK
  ^]
  telnet> quit
  Connection closed.
  ```

- Viewing the Redis logs
  ```
  # journalctl -u crio --no-pager
  ```

- Stop the redis container and delete the Pod
  ```
  # crictl stop 407b05f5d26f9
  # crictl rm 407b05f5d26f9
  # crictl stopp 9b60a39cf9141
  # crictl rmp 9b60a39cf9141
  ```



## 1.4 k8s中使用crio

- 确保`crio.service `服务先于`kubelet.service`服务启动： 

```
# cat /etc/systemd/system/kubelet.service | grep Wants
Wants=docker.socket crio.service
```

- 修改kubelet启动参数：

  - `--container-runtime=remote` - Use remote runtime with provided socket.
  - `--container-runtime-endpoint=unix:///var/run/crio/crio.sock` - Socket for remote runtime (default `crio` socket localization).
  - --cni-bin-dir=/usr/libexec/cni/ 
  - --cni-conf-dir=/etc/cni/net.d 
  - --network-plugin=cni

- 设置网络

  ```
  # cat /etc/cni/net.d/10-mynet.conf
  {
      "name": "mynet",
      "type": "flannel"
  }
  ```

  然后，kubelet将从/run/flannel/subnet.env获取参数 - 由flannel kubelet微服务生成的文件。

- 启动服务

  ```
  # systemctl start crio
  # systemctl start kubelet
  ```

  ​

# 2. papus容器

## 2.1 pod

pod是一组一个或多个容器的集合（如Docker容器），共享存储/网络，以及容器的运行规范。 pod的容器始终位于同一位置并共同调度，共享上下文。pod的共享上下文是一组Linux命名空间，cgroup等。

pod中的容器共享IP地址和端口空间，并且可以通过localhost通讯。 它们还可以使用SystemV信号量或POSIX共享内存等标准进程间通信相互通信。 不同pod中的容器具有不同的IP地址，并且在没有特殊配置的情况下无法通过IPC进行通信。 这些容器通常通过Pod IP地址相互通信。

## 2.2 共享命名空间

当运行新进程时，该进程从父进程继承名称空间。 如果需要在新的命名空间中运行进程，则需要 unshare 父进程的命名空间，从而创建新的命名空间：

```shell
# unshare --pid --uts --ipc --mount -f chroot rootfs /bin/sh
```

进程运行后，可以使用setns系统调用将新进程添加到现有命名空间 。

## 2.3 僵尸进程

PID命名空间中的所有进程会形成一个树结构，每个进程都会有一个父进程。在树的根部的进程没有父进程，这个进程就是init进程，PID为1。

进程可以使用**fork**和**exec** 系统调用启动其他进程。每个进程在进程表中都有一个条目，用于记录有关进程的状态和退出代码。当子进程运行完成，它的进程表条目仍然将保留直到父进程使用**wait** 检索其退出代码将其退出。这被称为回收僵尸进程。

当父进程在子进程完成后没有调用**wait** syscall时，会产生僵尸进程。僵尸进程由Init进程接管并回收。

容器通常都有自己的PID命名空间，ENTRYPOINT进程作为init进程。某个容器可以在另一个容器的命名空间中运行。在这种情况下，这个容器必须承担init进程的角色，而其他容器则作为init进程的子进程添加到命名空间中。

## 2.4 papus

原则上，任何人都可以配置Docker来控制容器之间的共享级别 --只需创建父容器，并正确的为新容器设置用于创建共享相同环境的标志，然后管理这些容器的生命周期。

k8s集群搭建需要下载一个`gcr.io/google_containers/pause-amd64:3.0`镜像。每次启动一个Pod，都会伴随一个pause容器的启动，pause容器又叫Infra容器，papus容器充当pod中所有其他容器的“父容器”。 papus容器有两个核心职责:

- 是pod中共享命名空间的基础。
- 启用PID命名空间共享后，它将作为每个pod的PID 1并获取僵尸进程。

以下示例如何使用pause容器和共享命名空间从头开始创建pod。 

- 首先，需要使用Docker启动papus容器，以便将容器添加到pod中。
  ```shell
  # docker run -d --name pause -p 8080:80 gcr.io/google_containers/pause-amd64:3.0
  ```

- 启动nginx容器

  ```shell
  $ cat <<EOF >> nginx.conf
  > error_log stderr;
  > events { worker_connections  1024; }
  > http {
  >     access_log /dev/stdout combined;
  >     server {
  >         listen 80 default_server;
  >         server_name example.com www.example.com;
  >         location / {
  >             proxy_pass http://127.0.0.1:2368;
  >         }
  >     }
  > }
  > EOF
  $ docker run -d --name nginx -v `pwd`/nginx.conf:/etc/nginx/nginx.conf --net=container:pause --ipc=container:pause --pid=container:pause nginx
  ```

- 启动ghost容器

  ```shell
  $ docker run -d --name ghost --net=container:pause --ipc=container:pause --pid=container:pause ghost
  ```

  现在访问 <http://localhost:8880/> 就可以看到ghost博客的界面了


pause容器在宿主机上设置好了网络namespace并将内部的80端口映射到宿主机的8880端口，nginx容器加入到该网络namespace中(`--net=container:pause` )，ghost容器同样加入到了该网络namespace中。这样三个容器就共享了网络，互相之间就可以使用 `localhost` 直接通信， init进程为 `pause` 。此时ghost容器中进程情况如下：

```shell
# ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   1024     4 ?        Ss   13:49   0:00 /pause
root         5  0.0  0.1  32432  5736 ?        Ss   13:51   0:00 nginx: master p
systemd+     9  0.0  0.0  32980  3304 ?        S    13:51   0:00 nginx: worker p
node        10  0.3  2.0 1254200 83788 ?       Ssl  13:53   0:03 node current/in
root        79  0.1  0.0   4336   812 pts/0    Ss   14:09   0:00 sh
root        87  0.0  0.0  17500  2080 pts/0    R+   14:10   0:00 ps aux
```

在ghost容器中同时可以看到pause和nginx容器的进程，并且pause容器的PID是1。而在kubernetes中容器的PID=1的进程即为容器本身的业务进程。

>参考：https://www.ianlewis.org/en/almighty-pause-container

# 4. CRI-O

CRI-O是容器运行时接口(CRI)的一个实现，可以使用OCI兼容的运行时。 它可以作为一个轻量级替代方案，以替换Docker作为kubernetes运行时。 它允许Kubernetes使用任何符合OCI的运行时作为运行pod的容器运行时。 目前支持runc和Clear Containers作为容器运行时，但原则上可以使用任何符合OCI标准的运行时。

CRI-O支持OCI容器images，可以从任何容器registry中拉取 images。 它是使用Docker/rkt作为Kubernetes运行时的轻量级替代品。

crio架构如下：

![crio](./Picture/cri_o.png)

- Pod是一个kubernetes概念，由一个或多个容器组成，这些容器共享相同的IPC，NET和PID名称空间并且位于同一个cgroup中。
- kublet通过kubernetes CRI将请求发送给CRI-O守护程序以启动新的POD。
- CRI-O使用`containers/image` 库从容器registry中拉取images。
- 下载的images使用`containers/storage`库解压缩到容器的根文件系统中，存储在COW文件系统中。
- 在为容器创建rootfs之后，CRI-O生成一个OCI运行时规范json文件，该文件描述了如何使用OCI 工具运行容器。
- CRI-O使用该规范启动OCI兼容运行时以运行容器程序。默认的OCI运行时是runc。
- 每个容器都由一个单独的conmon进程监视。 conmon进程保存容器进程的PID1的pty。它处理容器的日志并记录容器进程的退出代码。
- pod的网络通过CNI来设置，因此任何CNI插件都可以与CRI-O一起使用。


crio接口实现在server目录，分为三类：container_xxx.go，sandbox_xxx.go，image_xxx.go
- image_xxx.go
  ```go
  [server/image_xxx.go]
  ListImages
    -> s.StorageImageServer().ListImages()

  PullImage
    -> s.StorageImageServer().ResolveNames(image)
    -> s.StorageImageServer().CanPull(img, options)
    -> s.StorageImageServer().ImageStatus(s.ImageContext(), img)
    -> s.StorageImageServer().PrepareImage(s.ImageContext(), img, options)
    -> s.StorageImageServer().PullImage(s.ImageContext(), img, options)
    -> s.StorageImageServer().ImageStatus(s.ImageContext(), pulled)

  RemoveImage
    -> s.StorageImageServer().ResolveNames(image)
    -> s.StorageImageServer().UntagImage(s.ImageContext(), img)

  ImageStatus
    -> s.StorageImageServer().ResolveNames(image)
    -> s.StorageImageServer().ImageStatus(s.ImageContext(), image)

  ImageFsInfo
    -> s.StorageImageServer().GetStore()
  ----------------------------------------------------------------------
  [pkg/storage/image.go]
  ListImages
  ImageStatus
  CanPull
  PrepareImage
  PullImage
  UntagImage
  RemoveImage
  GetStore
  ResolveName
  ```

- sandbox_xxx.go

  k8s中，每个Pod都会伴随一个pause容器，kubelet创建Pod时首先会创建并启动一个papus容器充当pod中所有其他容器的父容器。kubelet通过调用crio的RunPodSandbox创建并启动一个pod级别的sandbox(papus容器)，其本质上仍是一个容器。

  ```go
  [server/sandbox_xxx.go]
  RunPodSandbox
    -> s.StorageRuntimeServer().CreatePodSandbox()//调用pkg/storage中的CreatePodSandbox

    -> sandbox.New()
    -> s.addSandbox(sb)
    -> s.PodIDIndex().Add(id)
    -> sb.NetNsCreate()    //创建网络namespace

    -> mountPoint := s.StorageRuntimeServer().StartContainer(id) //获取容器的mountPoint
    -> container, err := oci.NewContainer()//Container表示运行时的容器,该处创Container对象
    -> container.SetMountPoint(mountPoint)
    -> container.SetIDMappings(s.defaultIDMappings)
    -> container.SetSpec(g.Spec())
    -> sb.SetInfraContainer(container)
    -> s.addInfraContainer(container)
    -> s.createContainer()
       -> s.Runtime().CreateContainer()     //调用oci中的CreateContainer创建papus容器
    -> s.Runtime().StartContainer()         //调用oci中的StartContainer启动papus容器
    -> s.ContainerStateToDisk(container)    //将容器状态信息以json格式保存到磁盘中

  ListPodSandbox
    -> s.ContainerServer.ListSandboxes()

  PodSandboxStatus
    -> s.Runtime().ContainerStatus(podInfraContainer)

  StopPodSandbox
    -> xxx

  sandbox_network  
    -> networkStart
      -> newPodNetwork(sb)
      -> s.hostportManager.Add
    -> getSandboxIP
      -> podNetwork := newPodNetwork(sb)
      -> s.netPlugin.GetPodNetworkStatus(podNetwork)
    ->networkStop
      -> s.hostportManager.Remove()
      -> podNetwork := newPodNetwork(sb)
      -> s.netPlugin.TearDownPod(podNetwork)

  RemovePodSandbox
    -> s.StorageRuntimeServer().StopContainer(c.ID())
    -> s.StorageRuntimeServer().DeleteContainer(c.ID())
    -> s.StorageRuntimeServer().StopContainer(sb.ID())
    -> s.StorageRuntimeServer().RemovePodSandbox(sb.ID())
  ```

- container_xxx.go
  ```go
  [server/container_xxx.go]
  CreateContainer
    -> container, err := s.createSandboxContainer()        //调用pkg/storage中的
                                                           //CreateContainer
       -> s.Runtime().ContainerStatus(sb.InfraContainer())//获取infra 容器的状态，将新创建
                                                          //的容器加入infra的namespace中
       -> containerInfo, err := s.StorageRuntimeServer().CreateContainer
       -> mountPoint, err    := s.StorageRuntimeServer().StartContainer
       -> container, err := oci.NewContainer()
    -> s.addContainer(container)
    -> s.CtrIDIndex().Add(containerID)
    -> s.createContainer
       -> s.Runtime().CreateContainer
    -> s.ContainerStateToDisk(container)

  StartContainer
    -> s.Runtime().ContainerStatus(c)
    -> s.Runtime().StartContainer(c)
  ------------------------------------------------------------------------
  [oci/oci.go]

  CreateContainer
  StartContainer
  UpdateContainer
  ContainerStatus
  PauseContainer
  UnpauseContainer
  StopContainer
  DeleteContainer
  ExecSync

  SetStartFailed
  UpdateStatus
  WaitContainerStateStopped
  ```

- pkg/storage/{image.go,runtime.go}

  ```go
  [pkg/storage/image.go]
  type imageService struct {
          store                 storage.Store
          defaultTransport      string
          insecureRegistryCIDRs []*net.IPNet
          indexConfigs          map[string]*indexInfo          
          registries            []string 
          imageCache            imageCache
          imageCacheLock        sync.Mutex
          ctx                   context.Context                
  }  

  +CanPull
  +GetStore
  +ImageStatus
  +ListImages
  +PrepareImage
  +PullImage
  +RemoveImage
  +ResolveNames
  +UntagImage
  ------------------------------------------------------------------------
  [pkg/storage/runtime.go]
  type runtimeService struct {                                                                                                                               
          storageImageServer ImageServer                                                                                                                     
          pauseImage         string                                                                                                                          
          ctx                context.Context                                                                                                                 
  }

  +CreatePodSandbox
    -> createContainerOrPodSandbox
       -> istorage.Transport.ParseStoreReference
       -> istorage.Transport.GetStoreImage
          -> r.storageImageServer.PullImage
          -> istorage.Transport.GetStoreImage //如果image不存在，则通过image库拉取images
       -> r.storageImageServer.GetStore().CreateContainer //在磁盘中创建运行container
                                                          //所需的根文件系统layer
       -> r.storageImageServer.GetStore().Names(container.LayerID)
       -> r.storageImageServer.GetStore().SetNames   //设置container layer名称便于跟踪
       -> r.storageImageServer.GetStore().ContainerDirectory
       -> r.storageImageServer.GetStore().ContainerRunDirectory //检查container工作目录

  +RemovePodSandbox
    -> r.storageImageServer.GetStore().Container
    -> r.storageImageServer.GetStore().DeleteContainer
  +GetContainerMetadata
  +SetContainerMetadata
  +CreateContainer
  +DeleteContainer
  +StartContainer
    -> r.storageImageServer.GetStore().Container
    -> r.storageImageServer.GetStore().Mount
  +StopContainer
    -> r.storageImageServer.GetStore().Container
    -> r.storageImageServer.GetStore().Unmount
  +GetWorkDir
  +GetRunDir
  ```

  ​

# 5. CNI

kubelet以cni插件来支持cni规范，通过cni插件调用其他厂商开发的遵循cni规范的各种网络插件，如`Calico`,`Flannel`等。

## 5.1 ocicni

CRI-O守护进程通过[ocicni](https://github.com/cri-o/ocicni) API层调用CNI插件，并通过**monitorNetDirChan** channel监控cni插件目录配置文件的变化调用对应的插件。ocicni层接口如下：

```go
// PortMapping maps to the standard CNI portmapping Capability
// see: https://github.com/containernetworking/cni/blob/master/CONVENTIONS.md
type PortMapping struct {
	HostPort int32 `json:"hostPort"`
	ContainerPort int32 `json:"containerPort"`
	Protocol string `json:"protocol"`
	HostIP string `json:"hostIP"`
}

// PodNetwork configures the network of a pod sandbox.
type PodNetwork struct {
	Name string				    // sandbox名称.
	Namespace string		    // sandbox的namespace.
	ID string				    // sandbox container的ID.
	NetNS string			    // sandbox的网络namespace路径.
	PortMappings []PortMapping	// sandbox的端口映射.
}

// CNIPlugin is the interface that needs to be implemented by a plugin
type CNIPlugin interface {
	Name() string		// Name returns the plugin's name. 
	SetUpPod(network PodNetwork) (types.Result, error)
	TearDownPod(network PodNetwork) error
	GetPodNetworkStatus(network PodNetwork) (string, error)
	Status() error
}
```

接口说明如下：
`Name()` ： 返回插件的名称。在按名称搜索插件时将使用此选项。
`SetUpPod()`: 该方法在创建pod的沙箱容器之后但在启动pod的其他容器之前调用。
`TearDownPod()`：该方法在删除pod的沙箱容器之前调用.
`GetPodNetworkStatus()`：获取pod的沙箱容器的ipv4/ipv6地址。
`Status()`：返回网络的错误状态。

调用路径：
```go
[ocicni/ocicni.go]
SetUpPod     -> plugin.loNetwork.addToNetwork(podNetwork)
             -> plugin.getDefaultNetwork().addToNetwork(podNetwork)
                -> addToNetwork      -> cninet.AddNetworkList
TearDownPod  -> deleteFromNetwork -> cninet.DelNetworkList
GetPodNetworkStatus  -> getContainerIP
Status       -> plugin.checkInitialized() -> plugin.getDefaultNetwork()
```

## 5.2 CNI

CNI接口实现如下，cricni最终调用CNI的`AddNetworkList`和`DelNetworkList`两个接口：
```go
type CNI interface {
	AddNetworkList(net *NetworkConfigList, rt *RuntimeConf) (types.Result, error)
	GetNetworkList(net *NetworkConfigList, rt *RuntimeConf) (types.Result, error)
	DelNetworkList(net *NetworkConfigList, rt *RuntimeConf) error

	AddNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
	GetNetwork(net *NetworkConfig, rt *RuntimeConf) (types.Result, error)
	DelNetwork(net *NetworkConfig, rt *RuntimeConf) error
	
	ValidateNetworkList(net *NetworkConfigList) ([]string, error)
	ValidateNetwork(net *NetworkConfig) ([]string, error)
}
```

包含NetworkConfigList，RuntimeConf两个输入参数，NetworkConfigList保存网络配置，RuntimeConf保存CNI插件调用的参数:
```go
 // NetConf describes a network.
 type NetConf struct {
         CNIVersion string `json:"cniVersion,omitempty"`
         Name         string          `json:"name,omitempty"`
         Type         string          `json:"type,omitempty"`
         Capabilities map[string]bool `json:"capabilities,omitempty"`
         IPAM         IPAM            `json:"ipam,omitempty"`
         DNS          DNS             `json:"dns"`
 }

type NetworkConfig struct {
	Network *types.NetConf
	Bytes   []byte
}

type NetworkConfigList struct {
	Name       string
	CNIVersion string
	Plugins    []*NetworkConfig
	Bytes      []byte
}
```

```go
type RuntimeConf struct {
        ContainerID string         //容器ID
        NetNS       string         //容器NS
        IfName      string         //容器内网卡名称
        Args        [][2]string        
        CapabilityArgs map[string]interface{}                                       
        CacheDir string
}
```

调用路径：
```go
[containernetworking/cni/libcni/api.go]
AddNetworkList
  -> addOrGetNetworkList("ADD", nil, list, rt)
    -> addOrGetNetwork(command, list.Name, list.CNIVersion, net, prevResult, rt)
      -> invoke.ExecPluginWithResult(pluginPath, newConf.Bytes, c.args(command, rt), c.exec)

DelNetworkList
  -> delNetwork(list.Name, list.CNIVersion, net, cachedResult, rt)
    -> invoke.ExecPluginWithoutResult(pluginPath, newConf.Bytes, c.args("DEL", rt), c.exec) 
```

CNI接口通过invoke模块最终调用具体的Plugins。

## 5.3 plugins

每个网络有自己对应的插件和唯一的名称。CNI Plugin需要提供两个命令：一个用来将网络接口加入到指定网络Namespace，另一个用来将其移除。这两个接口分别在容器被创建和销毁的时候被调用。

- 容器运行时必须在调用任何插件之前为容器创建新的网络命名空间。
- 运行时必须确定此容器应属于哪些网络，并且对于每个网络，必须确定必须执行哪些插件。
- 网络配置采用JSON格式存储在文件中。网络配置包括必需字段，例如“name”和“type”以及插件（类型）特定字段。网络配置允许字段在调用时更改值。因此可选字段“args”必须包含变化的信息。
- 容器运行时必须通过按顺序为每个网络执行相应的插件，将容器添加到每个网络。
- 完成容器生命周期后，运行时必须以相反的顺序执行插件（相对于执行它们以添加容器的顺序）以断开容器与网络的连接。
- 容器运行时不能为同一容器调用并行操作，但允许为不同容器调用并行操作。
- 容器运行时必须为容器依次ADD和DEL操作，这样ADD总是最后跟随相应的DEL。 DEL之后可能有其他DEL，但插件应该允许多个DEL处理（即插件DEL应该是幂等的）。
- 容器必须由ContainerID唯一标识。插件存储状态应使用主键 `(network name, CNI_CONTAINERID, CNI_IFNAME)`.执行此操作。
- 运行时不能为相同的（网络名称，容器ID，容器内的接口名称）调用ADD两次（没有相应的DEL）。这意味着只有在使用不同的接口名称进行每次添加时，才能将给定的容器ID多次添加到特定网络。

### 5.3.1 接口实现

每个plugin必须实现以下接口(v0.4.0)：
- cmdAdd
- cmdDel
- cmdGet
- VERSION

接口输入参数由CmdArgs表示，
```go
// CmdArgs captures all the arguments passed in to the plugin
// via both env vars and stdin
type CmdArgs struct {
        ContainerID string
        Netns       string      // /proc/[pid]/ns/net 
        IfName      string
        Args        string
        Path        string
        StdinData   []byte
}
```


CNI的实现依赖于三种plugin：main Plugin将网络接口插入容器网络命名空间（例如，veth对的一端）并在主机上进行任何必要的设置（例如，将veth的另一端连接到桥中）。IPAM Plugin负责配置容器namespace中的网络参数(例如，为接口分配IP并设置路由等)。meta Plugin通常作为其他插件的附加插件使用。

### 5.3.2 main Plugin

- loopback
- bridge
- ipvlan
- macvlan
- ptp
- vlan
- host-device

### 5.3.3 IPAM Plugin

ipam用于管理容器的IP地址（包括网关、路由等信息)，CNI Plugin在运行时自动调用IPAM Plugin完成容器IP地址的分配。包含以下三种类型：

- dhcp
  使用dhcp插件时，容器可以通过DHCP服务器分配的IP，这对于诸如macvlan之类的插件类型尤其有用。
  由于必须在容器生存期内定期更新DHCP租约，因此dhcp插件需要在守护进程模式下运行。
  ```
  # rm -f /run/cni/dhcp.sock
  # ./dhcp daemon
  ```

  配置示例：
  ```
   "ipam": {
       "type": "dhcp",
   }
  ```

- host-local
  host-local从指定的地址范围中分配IPv4和IPv6地址。它可以包含主机上resolv.conf文件的DNS配置。host-local会将状态存储在主机文件系统上，从而确保单个主机上IP地址的唯一性。分配器可以分配多个范围IP，并支持多个子网集(不相交)。 分配策略在每个范围集内都是松散循环的。

  配置示例1：
  ```json
   "ipam": {
       "type": "host-local",
       "subnet": "10.88.0.0/16",
       "routes": [
           { "dst": "0.0.0.0/0" }
       ]
   }
  ```

  配置示例2：
  ==<待补充>==

- static
  static PAM是一种非常简单的IPAM插件，可以将IPv4和IPv6地址静态分配给容器。 在调试或者将不同vlan / vxlan中的相同IP地址分配给容器时非常有用。

  配置示例：
  ```json
  	"ipam": {
  		"type": "static",
  		"addresses": [
  			{
  				"address": "10.10.0.1/24",
  				"gateway": "10.10.0.254"
  			},
  			{
  				"address": "3ffe:ffff:0:01ff::1/64",
  				"gateway": "3ffe:ffff:0::1"
  			}
  		],
  		"routes": [
  			{ "dst": "0.0.0.0/0" },
  			{ "dst": "192.168.0.0/16", "gw": "10.10.5.1" },
  			{ "dst": "3ffe:ffff:0:01ff::1/64" }
  		],
  		"dns": {
  			"nameservers" : ["8.8.8.8"],
  			"domain": "example.com",
  			"search": [ "example.com" ]
  		}
  	}
  ```

### 5.3.4 meta Plugin

- flannel

  该插件用于和flannel关联，当flannel守护进程启动后，会在 `/run/flannel/subnet.env` 文件中输出以下变量：

  ```
  FLANNEL_NETWORK=10.1.0.0/16
  FLANNEL_SUBNET=10.1.17.1/24
  FLANNEL_MTU=1472
  FLANNEL_IPMASQ=true
  ```

  此信息反映了主机上flannel网络的属性。flannel CNI插件使用此信息配置另一个CNI插件，例如桥接插件。

  配置示例：

  基于上述flannel变量，配置以下文件

  ```
  {
  	"name": "mynet",
  	"type": "flannel"
  }
  ```

  flannel插件会生成另外一个网络配置文件：

  ```json
  {
  	"name": "mynet",
  	"type": "bridge",
  	"mtu": 1472,
  	"ipMasq": false,
  	"isGateway": true,
  	"ipam": {
  		"type": "host-local",
  		"subnet": "10.1.17.0/24"
  	}
  }
  ```

  从上面可以看出，默认情况下，flannel插件将委托给bridge插件。如果需要将其他配置值传递给bridge插件，可以通过`delegate`完成：

  ```json
  {
  	"name": "mynet",
  	"type": "flannel",
  	"delegate": {
  		"bridge": "mynet0",
  		"mtu": 1400
  	}
  }
  ```

  上述配置将创建的网桥名修改为mynet0，同时还指定了mtu值，并且这个值不会被flannel插件覆盖。此外，还可以通过`delegate`选择不同类型的插件。

  ```json
  {
  	"name": "mynet",
  	"type": "flannel",
  	"delegate": {
  		"type": "ipvlan",
  		"master": "eth0"
  	}
  }
  ```

- bandwidth

  该插件提供了一种使用和配置Linux的流量控制（tc）子系统的方法。 该插件在入口和出口流量上配置令牌桶过滤器（tbf）排队规则（qdisc）。 由于入口的tc规则的限制，此插件创建了一个ifb(中间功能块)设备重定向来自主机接口的数据包。 然后将tc tbf应用于ifb设备。 重定向到ifb设备的数据包被写入（并整形）到主机接口。

  该插件仅在与其他插件一起使用时才有用。

  配置示例：

  ```json
  {
    "cniVersion": "0.3.1",
    "name": "mynet",
    "plugins": [
      {
        "type": "ptp",
        "ipMasq": true,
        "mtu": 512,
        "ipam": {
            "type": "host-local",
            "subnet": "10.0.0.0/24"
        },
        "dns": {
          "nameservers": [ "10.1.0.1" ]
        }
      },
      {
        "name": "slowdown",
        "type": "bandwidth",
        "ingressRate": 123,
        "ingressBurst": 456,
        "egressRate": 123,
        "egressBurst": 456
      }
    ]
  }
  ```

- portmap

  portmap插件将流量从主机上的一个或多个端口转发到容器。该插件作为链接插件运行。

  配置示例：

  ```json
          "cniVersion": "0.3.1",
          "name": "mynet",
          "plugins": [
                  {
                          "type": "ptp",
                          "ipMasq": true,
                          "ipam": {
                                  "type": "host-local",
                                  "subnet": "172.16.30.0/24",
                                  "routes": [
                                          {
                                                  "dst": "0.0.0.0/0"
                                          }
                                  ]
                          }
                  },
                  {
                          "type": "portmap",
                          "capabilities": {"portMappings": true},
                          "snat": true,
                          "markMasqBit": 13,
                          "externalSetMarkChain": "CNI-HOSTPORT-SETMARK",
                          "conditionsV4": ["!", "-d", "192.0.2.0/24"],
                          "conditionsV6": ["!", "-d", "fc00::/7"]
                  }
          ]
  ```

  - snat：默认为true。 如果为true或省略，则设置SNAT链。
  - markMasqBit：int型，范围0-31，默认为13。用于MASQUERADE(参考SNAT)。 使用externalSetMarkChain时无法设置。
  - externalSetMarkChain：string型，默认为零。 如果已经拥有MASQUERADE(例如Kubernetes)，需请在此处指定。 这会使用kubernetes中的链而不是创建一个单独的链。 设置此项后，必须取消指定markMasqBit
  - 字符串数组。 添加到每容器规则之前iptables规则。常用于从portMappings中排除特定IP。

- tuning

  用于更改网络命名空间中的某些系统参数（sysctls）。该插件不会创建任何网络接口，仅作为其他插件的附件插件使用。

  使用示例：

  ```json
    "name": "mytuning",
    "type": "tuning",
    "sysctl": {
            "net.core.somaxconn": "500"
    }
  ```


## 5.4 网络配置规范

- Network Configuration
  包含以下配置：
  - cniVersion
  - name
  - type
  - args
  - ipMasq
  - ipam
    - type
  - dns
    - nameservers
    - domain
    - search
    - options

  配置示例：
  ```json
  {
    "cniVersion": "0.4.0",
    "name": "dbnet",
    "type": "bridge",
    // type (plugin) specific
    "bridge": "cni0",
    "ipam": {
      "type": "host-local",
      // ipam specific
      "subnet": "10.1.0.0/16",
      "gateway": "10.1.0.1"
    },
    "dns": {
      "nameservers": [ "10.1.0.1" ]
    }
  }
  ```

  ```json
  {
    "cniVersion": "0.4.0",
    "name": "pci",
    "type": "ovs",
    // type (plugin) specific
    "bridge": "ovs0",
    "vxlanID": 42,
    "ipam": {
      "type": "dhcp",
      "routes": [ { "dst": "10.3.0.0/16" }, { "dst": "10.4.0.0/16" } ]
    }
    // args may be ignored by plugins
    "args": {
      "labels" : {
          "appVersion" : "1.0"
      }
    }
  }
  ```

  ```json
  {
    "cniVersion": "0.4.0",
    "name": "wan",
    "type": "macvlan",
    // ipam specific
    "ipam": {
      "type": "dhcp",
      "routes": [ { "dst": "10.0.0.0/8", "gw": "10.0.0.1" } ]
    },
    "dns": {
      "nameservers": [ "10.0.0.1" ]
    }
  }
  ```

- Network Configuration Lists
  可以按照定义的顺序为单个容器运行多个CNI插件，并将每个插件的结果传递给下一个插件。包含以下配置：
  - cniVersion
  - name
  - plugins(list)

  配置示例:
  ```json
  {
    "cniVersion": "0.4.0",
    "name": "dbnet",
    "plugins": [
      {
        "type": "bridge",
        // type (plugin) specific
        "bridge": "cni0",
        // args may be ignored by plugins
        "args": {
          "labels" : {
              "appVersion" : "1.0"
          }
        },
        "ipam": {
          "type": "host-local",
          // ipam specific
          "subnet": "10.1.0.0/16",
          "gateway": "10.1.0.1"
        },
        "dns": {
          "nameservers": [ "10.1.0.1" ]
        }
      },
      {
        "type": "tuning",
        "sysctl": {
          "net.core.somaxconn": "500"
        }
      }
    ]
  }
  ```

  上述配置，ADD操作执行以下步骤(GET/DEL执行操作步骤类似)：
  1. 调用bridge插件配置cni0网络
  2. 根据bridge插件返回结果，调用tuning插件执行以下配置

     ```json
     {
       "cniVersion": "0.4.0",
       "name": "dbnet",
       "type": "tuning",
       "sysctl": {
         "net.core.somaxconn": "500"
       },
       "prevResult": {
         "ips": [
             {
               "version": "4",
               "address": "10.0.0.5/32",
               "interface": 2
             }
         ],
         "interfaces": [
             {
                 "name": "cni0",
                 "mac": "00:11:22:33:44:55",
             },
             {
                 "name": "veth3243",
                 "mac": "55:44:33:22:11:11",
             },
             {
                 "name": "eth0",
                 "mac": "99:88:77:66:55:44",
                 "sandbox": "/var/run/netns/blue",
             }
         ],
         "dns": {
           "nameservers": [ "10.1.0.1" ]
         }
       }
     }
     ```


## 5.5 扩展规范
使用CNI将信息传递给插件有三种方法：
- JSON配置中的插件特定字段
- JSON配置中的args字段
- CNI_ARGS环境变量


建立这些规范可以允许插件跨多个运行时工作。因此Plugins和Runtimes必须遵守该规范。

- Dynamic Plugin specific fields

  - portmap plugin:  portMappings
  - host-local Plugin:  ipRanges
  - bandwidth Plugin:  bandwidth

- args

  - labels

    ```json
    {  
       "cniVersion":"0.2.0",
       "name":"net",
       "args":{  
          "cni":{  
             "labels": [{"key": "app", "value": "myapp"}]
          }
       },
       "ipam":{  
       }
    }
    ```

  - ips

- CNI_ARGS(deprecated)










































