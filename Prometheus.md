

# 1. Prometheus

##1.1 Prometheus架构

![prometheus](./Picture/prometheus.png)

- **Prometheus Server**: 用于收集和存储时间序列数据。
- **Client Library**: 客户端库，为需要监控的服务生成相应的 metrics 并暴露给 Prometheus server。当 Prometheus server 来 pull 时，直接返回实时状态的 metrics。
- **Push Gateway**: 主要用于短期的 jobs。由于这类 jobs 存在时间较短，可能在 Prometheus 来 pull 之前就消失了。为此，这次 jobs 可以直接向 Prometheus server 端推送它们的 metrics。这种方式主要用于服务层面的 metrics，对于机器层面的 metrices，需要使用 node exporter。
- **Exporters**: 用于暴露已有的第三方服务的 metrics 给 Prometheus。
- **Alertmanager**: 从 Prometheus server 端接收到 alerts 后，会进行去除重复数据，分组，并路由到对收的接受方式，发出报警。常见的接收方式有：电子邮件，pagerduty，OpsGenie, webhook 等。
- 一些其他的工具。


##1.2 工作流程

1. Prometheus server 定期从配置好的 jobs 或者 exporters 中拉 metrics，或者接收来自 Pushgateway 发过来的 metrics，或者从其他的 Prometheus server 中拉 metrics。
2. Prometheus server 在本地存储收集到的 metrics，并运行已定义好的 alert.rules，记录新的时间序列或者向 Alertmanager 推送警报。
3. Alertmanager 根据配置文件，对接收到的警报进行处理，发出告警。
4. 在图形界面中，可视化采集数据。


## 1.3 数据模型

Prometheus 中存储的数据为时间序列，是由 metric 的名字和一系列的标签（键值对）唯一标识的，不同的标签则代表不同的时间序列。

- metric 名字：该名字应该具有语义，一般用于表示 metric 的功能，例如：http_requests_total, 表示 http 请求的总数。其中，metric 名字由 ASCII 字符，数字，下划线，以及冒号组成，且必须满足正则表达式 [a-zA-Z_:][a-zA-Z0-9_:]*。
- 标签：使同一个时间序列有了不同维度的识别。例如 http_requests_total{method="Get"} 表示所有 http 请求中的 Get 请求。当 method="post" 时，则为新的一个 metric。标签中的键由 ASCII 字符，数字，以及下划线组成，且必须满足正则表达式 [a-zA-Z_:][a-zA-Z0-9_:]*。
- 样本：实际的时间序列，每个序列包括一个 float64 的值和一个毫秒级的时间戳。
- 格式：<metric name>{<label name>=<label value>, …}，例如：http_requests_total{method="POST",endpoint="/api/tracks"}。


## 1.4 Metric 类型

- **Counter**

  一种累加的 metric，典型的应用如：请求的个数，结束的任务数， 出现的错误数等等。例如，查询 http_requests_total{method="get", job="Prometheus", handler="query"} 返回 8，10 秒后，再次查询，则返回 14。

- **Gauge**

  一种常规的 metric，典型的应用如：温度，运行的 goroutines 的个数。可以任意加减。例如：go_goroutines{instance="172.17.0.2", job="Prometheus"} 返回值 147，10 秒后返回 124。

- **Histogram**

  - 可以理解为柱状图，典型的应用如：请求持续时间，响应大小。
  - 可以对观察结果采样，分组及统计。

- **Summary**

  - 类似于 Histogram, 典型的应用如：请求持续时间，响应大小。
  - 提供观测值的 count 和 sum 功能。
  - 提供百分位的功能，即可以按百分比划分跟踪结果。


#2. Prometheus 的配置

## 2.1 全局配置

```yaml
global:
  scrape_interval: 15s     # 数据收集的间隔
  scrape_timeout: 10s      # scrape请求超时时间
  evaluation_interval: 15s # 评估规则间隔

alerting:
#  alert_relabel_configs:
  alertmanagers:
  - static_configs:
    - targets:
      - 127.0.0.1:9093

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'  # 全局唯一。作为label添加到`job=<job_name>`
    scrape_interval: 10s    # default = <global_config.scrape_interval>
    scrape_timeout: 10s     # default = <global_config.scrape_timeout>
    metrics_path: /metrics  # default = /metrics
    honor_labels: true      # default = false
    scheme: https           # default = http
    params:                 # Optional HTTP URL parameters.

    basic_auth:
      [ username: <string> ]
      [ password: <secret> ]
      [ password_file: <string> ]
    bearer_token: <secret>
    bearer_token_file: /path/to/bearer/token/file
    tls_config:             # TLS 设置

    static_configs:
    - targets: ['192.168.56.101:9100']    # node exporter
    
    kubernetes_sd_configs:
    relabel_configs:
    metric_relabel_configs:

#remote_write:
#remote_read:
```

## 2.2 kubernetes_sd_config

Kubernetes SD配置允许从Kubernetes的REST API中检索scrape目标，并始终与群集状态保持同步。主要支持以下5种服务发现模式：

可以通过配置以下角色类型来发现目标：

### 2.2.1 node

通过指定kubernetes_sd_config的模式为node，Prometheus会自动从Kubernetes中发现所有的node节点并作为当前Job监控的Target实例，target地址默认选择顺序为NodeInternalIP，NodeExternalIP，NodeLegacyHostIP和NodeHostName。端口默认为Kubelet的HTTP端口。

```yaml
- job_name: 'kubernetes-nodes'
  tls_config:
    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    insecure_skip_verify: true
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  kubernetes_sd_configs:
  - role: node
  relabel_configs:
  - action: labelmap
    regex: __meta_kubernetes_node_label_(.+)
```

通过labelmap，将Node节点上的标签，作为样本的标签保存到时间序列当中。

可用的meta标签如下：

- `__meta_kubernetes_node_name`: 节点名。
- `__meta_kubernetes_node_label_<labelname>`: 节点标签。
- `__meta_kubernetes_node_annotation_<annotationname>`: 节点注释。
- `__meta_kubernetes_node_address_<address_type>`: 节点第一个地址。

或者通过API代理访问各个节点中kubelet的metrics服务

```yaml
  - job_name: 'kubernetes-kubelet'
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      kubernetes_sd_configs:
      - role: node
      relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      - target_label: __address__
        replacement: kubernetes.default.svc:443
      - source_labels: [__meta_kubernetes_node_name]
        regex: (.+)
        target_label: __metrics_path__
        replacement: /api/v1/nodes/${1}/proxy/metrics
```

#### 2.2.2 pod

```yaml
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
    - role: pod
    relabel_configs:
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
      action: keep
      regex: true
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
      action: replace
      target_label: __metrics_path__
      regex: (.+)
    - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
      action: replace
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:$2
      target_label: __address__
    - action: labelmap
      regex: __meta_kubernetes_pod_label_(.+)
    - source_labels: [__meta_kubernetes_namespace]
      action: replace
      target_label: kubernetes_namespace
    - source_labels: [__meta_kubernetes_pod_name]
      action: replace
      target_label: kubernetes_pod_name
```

### 2.2.3 service

```yaml
 - job_name: 'kubernetes-services'
      metrics_path: /probe
      params:
        module: [http_2xx]
      kubernetes_sd_configs:
      - role: service
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_probe]
        action: keep
        regex: true
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: __address__
        replacement: blackbox-exporter.default.svc.cluster.local:9115
      - source_labels: [__param_target]
        target_label: instance
      - action: labelmap
        regex: __meta_kubernetes_service_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_service_name]
        target_label: kubernetes_name
```

可用的meta标签如下:

- `__meta_kubernetes_namespace`:  namespace
- `__meta_kubernetes_service_name`:  名称
- `__meta_kubernetes_service_label_<labelname>`: 标签
- `__meta_kubernetes_service_annotation_<annotationname>`: annotation
- `__meta_kubernetes_service_port_name`:  port名称
- `__meta_kubernetes_service_port_number`: 端口号.
- `__meta_kubernetes_service_port_protocol`: Protocol

### 2.2.4 endpoint

```yaml
    - job_name: 'kubernetes-apiservers'
      kubernetes_sd_configs:
      - role: endpoints
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https
      - target_label: __address__
        replacement: kubernetes.default.svc:443
```

### 2.2.5 ingress

```yaml
  - job_name: 'kubernetes-ingresses'
      metrics_path: /probe
      params:
        module: [http_2xx]
      kubernetes_sd_configs:
      - role: ingress
      relabel_configs:
      - source_labels: [__meta_kubernetes_ingress_annotation_prometheus_io_probe]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_ingress_scheme,__address__,__meta_kubernetes_ingress_path]
        regex: (.+);(.+);(.+)
        replacement: ${1}://${2}${3}
        target_label: __param_target
      - target_label: __address__
        replacement: blackbox-exporter.default.svc.cluster.local:9115
      - source_labels: [__param_target]
        target_label: instance
      - action: labelmap
        regex: __meta_kubernetes_ingress_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_ingress_name]
        target_label: kubernetes_name
```

## 2.3 relabel_config

可以动态地重写目标的标签集。

```
[ source_labels: '[' <labelname> [, ...] ']' ]  # 选择源标签
[ separator: <string> | default = ; ]           # 分隔符
[ target_label: <labelname> ]                   # target标签
[ regex: <regex> | default = (.*) ]
[ modulus: <uint64> ]
[ replacement: <string> | default = $1 ]
[ action: <relabel_action> | default = replace ]
```

action项：

- replace: 根据source_labels匹配regex，并替换target_label
- keep：不匹配则丢弃目标
- drop：匹配则丢弃目标
- hashmod：
- labelmap：
- labeldrio：
- labelkeep：


##2.4 查询

Prometheus提供一个函数式的表达式语言，可以使用户实时地查找和聚合时间序列数据。表达式计算结果可以在图表中展示，也可以在Prometheus表达式浏览器中以表格形式展示，或者作为数据源, 以HTTP API的方式提供给外部系统使用， 如k8s等。

### 2.4.1 基本概念

- instant vector
  瞬时向量 - 在同一时刻，抓取的所有metrics数据。这些metrics数据的key都是相同的，即相同的时间戳。
- range vector
   范围向量 - 抓取任何一个时间范围内所有metrics数据。
- scalar 
  标量 - 浮点值
- string
  字符串 - 当前没有使用

依赖于使用场景，如图形，只有部分场景才适用这种表达式。例如：瞬时向量类型仅可以在图表中使用。

### 2.4.2 函数



### 2.4.3 示例

- 时间序列选择
  返回metric为`http_requests_total`的时间序列数据
  > http_requests_total
  
  返回metric为`http_requests_total`,标签为标签为`job="apiserver", handler="/api/comments"`的时间序列数据
  > http_requests_total{job="apiserver", handler="/api/comments"}
  
  返回5m内的上述range vector
  > http_requests_total{job="apiserver", handler="/api/comments"}[5m]

  使用正则表达式匹配标签为job,以server结尾的任务，获取这些任务的时间序列。s
  > http_requests_total{job=~".*server"}

  http状态码为非4开头的所有时间序列数据
  > http_requests_total{status!~"4.."}
- 函数/运算符
  metrics名称http_requests_total，过去5分钟的所有时间序列数据值速率。
  > rate(http_requests_total[5m])

  metrics名称为http_requests_total，过去5分钟的所有时间序列数据的速率和，速率的维度是job
  > sum(rate(http_requests_total[5m])) by (job)

  返回每一个实例剩余内存
  > (instance_memory_limit_byte - instant_memory_usage_bytes) / 1024 / 1024
  > 
  相同集群调度器任务，显示CPU使用率度
  > instance_cpu_time_ns{app=”lion”, pro=”web”, rev=”34d0f99”, env=”prod”, job=”cluster-manager”}
  > instance_cpu_time_ns{app=”elephant”, proc=”worker”, rev=”34d0f99”, env=”prod”, job=”cluster-manager”}
  > instance_cpu_time_ns{app=”turtle”, proc=”api”, rev=”4d3a513”, env=”prod”, job=”cluster-manager”}

  获取最高的3个CPU使用率，按照标签列表app和proc分组
  > topk(3, sum(rate(instance_cpu_time_ns[5m])) by(app, proc))

  假设一个服务实例只有一个时间序列数据，以下表达式统计出每个应用的实例数量：
  > count(instance_cpu_time_ns) by (app)


# 3. Alertmanager

当接收到 Prometheus 端发送过来的 alerts 时，Alertmanager 会对 alerts 进行去重复，分组，路由到对应集成的接受端，包括：slack，电子邮件，pagerduty，hitchat，webhook。

配置参照<node_export.yaml>

# 4. metrics

## 4.1 监控模式

需要综合使用白盒监控和黑盒监控模式，建立从基础设施，Kubernetes核心组件，应用容器等全面的监控体系

- 白盒监控
  - 基础设施层（Node）：为整个集群和应用提供运行时资源，需要通过各节点的kubelet获取节点的基本状态，同时通过在节点上部署Node Exporter获取节点的资源使用情况；
  - 容器基础设施（Container）：为应用提供运行时环境，Kubelet内置了对cAdvisor的支持，用户可以直接通过Kubelet组件获取给节点上容器相关监控指标；
  - 用户应用（Pod）：Pod中会包含一组容器，它们一起工作，并且对外提供一个（或者一组）功能。如果用户部署的应用程序内置了对Prometheus的支持，那么我们还应该采集这些Pod暴露的监控指标；
  - Kubernetes组件：获取并监控Kubernetes核心组件的运行状态，确保平台自身的稳定运行。
- 黑盒监控
  - 内部服务负载均衡（Service）：在集群内，通过Service在集群暴露应用功能，集群内应用和应用之间访问时提供内部的负载均衡。通过Balckbox Exporter探测Service的可用性，确保当Service不可用时能够快速得到告警通知；
  - 外部访问入口（Ingress）：通过Ingress提供集群外的访问入口，从而可以使外部客户端能够访问到部署在Kubernetes集群内的服务。因此也需要通过Blackbox Exporter对Ingress的可用性进行探测，确保外部用户能够正常访问集群内的功能；

Kubernetes集群监控的各个维度以及策略:

| 目标                                         | 服务发现模式 | 监控方法 | 数据源               |
| :--------------------------------------------| :----------| -------| ------------------- |
| 集群中各节点kubelet的基本运行状态的metrics        | node       | 白盒   | kubelet           |
| 集群中各节点内运行的容器的metrics                 | node       | 白盒   | cAdvisor          |
| 主机资源相关的metrics                           | node       | 白盒   | node exporter     |
| Pod实例中自定义metrics(内置了Promthues支持的应用) | pod         | 白盒  | custom pod        |
| Kubernetes集群相关的运行metrics                   | endpoints | 白盒  | api server        |
| 集群中Service的网络metrics                        | service   | 黑盒  | blackbox exporter |
| 集群中Ingress的网络metrics                        | ingress   | 黑盒  | blackbox exporter |

## 4.2 node_exporter

[**node_exporter**](https://github.com/prometheus/node_exporter)主要用于暴露节点cpu 负载、内存、网络等使用情况。当 node exporter 启动时，可以通过 curl <http://localhost:9100/metrics>查看系统的 metrics

```yaml
      - job_name: 'prometheus-node-exporter'

        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
        kubernetes_sd_configs:
        #The endpoints role discovers targets from listed endpoints of a service. For each
        #endpoint address one target is discovered per port. If the endpoint is backed by
        #a pod, all additional container ports of the pod, not bound to an endpoint port,
        #are discovered as targets as well
        - role: endpoints
        relabel_configs:
        # 只保留endpoints的annotations中含有prometheus.io/scrape: 'true'和port的name为prometheus-node-exporter的endpoint
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape, __meta_kubernetes_endpoint_port_name]
          regex: true;prometheus-node-exporter
          action: keep
        # Match regex against the concatenated source_labels. Then, set target_label to replacement, 
        # with match group references (${1}, ${2}, ...) in replacement substituted by their value. 
        # If regex does not match, no replacement takes place.
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scheme]
          action: replace
          target_label: __scheme__
          regex: (https?)
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)
        - source_labels: [__address__, __meta_kubernetes_service_annotation_prometheus_io_port]
          action: replace
          target_label: __address__
          regex: (.+)(?::\d+);(\d+)
          replacement: $1:$2
        # 去掉label name中的前缀__meta_kubernetes_service_label_
        - action: labelmap
          regex: __meta_kubernetes_service_label_(.+)
        # 将__meta_kubernetes_namespace重命名为kubernetes_namespace
        - source_labels: [__meta_kubernetes_namespace]
          action: replace
          target_label: kubernetes_namespace
        # 将__meta_kubernetes_service_name重命名为kubernetes_name
        - source_labels: [__meta_kubernetes_service_name]
          action: replace
          target_label: kubernetes_name
```



## 4.3 kube-state-metrics

[kube-state-metrics](https://github.com/kubernetes/kube-state-metrics)是一个简单的服务，用于监听Kubernetes API服务器并生成有关对象状态的metrics。kube-state-metrics不关注单个Kubernetes组件的运行状况，而是关注内部各种对象的运行状况，例如node、pod、service等。

- 部署

  ```yaml
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: kube-state-metrics
    namespace: kube-system
  ---
  apiVersion: extensions/v1beta1
  kind: Deployment
  metadata:
    name: kube-state-metrics
    namespace: kube-system
    labels:
      app: kube-state-metrics
  spec:
    replicas: 1
    template:
      metadata:
        labels:
          app: kube-state-metrics
      spec:
        serviceAccountName: kube-state-metrics
        containers:
        - name: kube-state-metrics
          image: daocloud.io/liukuan73/kube-state-metrics:v1.1.0
          ports:
          - containerPort: 8080
        restartPolicy: Always
        nodeSelector:
          node-role.kubernetes.io/master: "true"
        tolerations:
        - key: "node-role.kubernetes.io/master"
          effect: "NoSchedule"
  ---
  apiVersion: v1
  kind: Service
  metadata:
    annotations:
      prometheus.io/scrape: 'true'
      prometheus.io/http-probe: 'true'
      prometheus.io/http-probe-path: '/healthz'
      prometheus.io/http-probe-port: '8080'
      prometheus.io/scrape: 'true'
      prometheus.io/app-metrics: 'true'
      prometheus.io/app-metrics-path: '/metrics'
      prometheus.io/app-metrics-port: '8080'
    name: kube-state-metrics
    namespace: kube-system
    labels:
      app: kube-state-metrics
  spec:
    type: NodePort
    ports:
    - name: kube-state-metrics
      port: 8080
      targetPort: 8080
      nodePort: 30005
    selector:
      app: kube-state-metrics
  ```

- prometheus监控配置

  ```yaml
        - job_name: 'kube-state-metrics'

          tls_config:
            ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
          kubernetes_sd_configs:
          - role: endpoints
          relabel_configs:
          # 只保留endpoint中的annotations含有prometheus.io/scrape: 'true'和port的name为prometheus-node-exporter的endpoint
          - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape,__meta_kubernetes_endpoint_port_name]
            regex: true;kube-state-metrics
            action: keep
          - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scheme]
            action: replace
            target_label: __scheme__
            regex: (https?)
          - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
            action: replace
            target_label: __metrics_path__
            regex: (.+)
          - source_labels: [__address__, __meta_kubernetes_service_annotation_prometheus_io_port]
            action: replace
            target_label: __address__
            regex: (.+)(?::\d+);(\d+)
            replacement: $1:$2
          # 去掉label name中的前缀__meta_kubernetes_service_label_
          - action: labelmap
            regex: __meta_kubernetes_service_label_(.+)
          # 将__meta_kubernetes_namespace重命名为kubernetes_namespace
          - source_labels: [__meta_kubernetes_namespace]
            action: replace
            target_label: kubernetes_namespace
          # 将__meta_kubernetes_service_name重命名为kubernetes_name
          - source_labels: [__meta_kubernetes_service_name]
            action: replace
            target_label: kubernetes_name
  ```

  ​

### 4.2.1 metrics

kube-state-metrics通过 [Prometheus client_golang](https://github.com/prometheus/client_golang) 库在HTTP endpoint `/metrics`导出，主要用于Prometheus或兼容的scraper。

- [CronJob Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/cronjob-metrics.md)
- [DaemonSet Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/daemonset-metrics.md)
- [Deployment Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/deployment-metrics.md)
- [Job Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/job-metrics.md)
- [LimitRange Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/limitrange-metrics.md)
- [Node Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/node-metrics.md)
- [PersistentVolume Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/persistentvolume-metrics.md)
- [PersistentVolumeClaim Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/persistentvolumeclaim-metrics.md)
- [Pod Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/pod-metrics.md)
- [ReplicaSet Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/replicaset-metrics.md)
- [ReplicationController Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/replicationcontroller-metrics.md)
- [ResourceQuota Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/resourcequota-metrics.md)
- [Service Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/service-metrics.md)
- [StatefulSet Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/statefulset-metrics.md)
- [Namespace Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/namespace-metrics.md)
- [Horizontal Pod Autoscaler Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/horizontalpodautoscaler-metrics.md)
- [Endpoint Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/endpoint-metrics.md)
- [Secret Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/secret-metrics.md)
- [ConfigMap Metrics](https://github.com/kubernetes/kube-state-metrics/blob/master/Documentation/configmap-metrics.md)


另外，kube-state-metrics还在 `--telemetry-host` and `--telemetry-port` (default 81)中导出了自身的metrics

### 4.2.2 Resource recommendation

kube-state-metrics的资源使用情况随群集的Kubernetes对象（Pods / Nodes / Deployments / Secrects等）大小而变化。在某种程度上，群集中的Kubernetes对象与群集的节点编号成正比。  addon-resizer可以根据节点数观察并自动垂直缩放依赖容器。因此，kube-state-metrics使用addon-resizer自动扩展其资源请求。关于addon-resizer的详细用法，请访问其README。

### 4.2.3 kube-state-metrics vs. metrics-server

[metrics-server](https://github.com/kubernetes-incubator/metrics-server)项目用于从Kubernetes API server和Node获取metrics（如CPU和内存利用率），并将它们发送到各种时间序列后端，如InfluxDB或Google Cloud Monitoring。 它目前最重要的功能是实现Kubernetes组件的某些metric API，如horizontal pod autoscaler根据从metrics-server中查询的metrics来做出决策。

metrics-server重点是转发由Kubernetes生成的metrics，而kube-state-metrics的重点是从Kubernetes的对象状态生成全新的metrics（例如基于deployments，rc的metrics）。没有使用kube-state-metrics扩展metrics-server的原因是关注点不同：metrics-server只需要获取，格式化和转发已经存在的metrics，特别是来自Kubernetes组件的指标，并将它们写入接收器，这些接收器是实际的监控系统。相比，kube-state-metrics在内存中保存了Kubernetes状态的完整快照，并不断生成基于它的新metrics，但不负责导出metrics。换句话说，kube-state-metrics本身被设计为metrics-server的另一个源（尽管目前不是这种情况）。

此外，一些监控系统如Prometheus根本不使用metrics-server收集metrics，而是实现自己的，但Prometheus可以从heapster本身抓取metrics，以警告Heapster（metrics-server）的健康状况。 将kube-state-metrics作为单独的项目，可以从这些监视系统访问这些metrics。



## 4.3 k8s组件metrics

kube-apiserver：http://192.168.56.101:8080/metrics

kube-scheduler ： http://192.168.56.101:10251/metrics

kube-controlle：http://192.168.56.101:10252/metrics

kube-proxy：http://192.168.56.102:10249/metrics

kubelet： http://192.168.56.102:10255/metrics



## 4.4 cAdvisor

1.7.3版本以前，cadvisor的metrics数据集成在kubelet的metrics中，在1.7.3以后版本中cadvisor的metrics被从kubelet的metrics独立出来：

cAdvisor ： NodeIP:10255/metrics/cadvisor

另外，kubelet提供了stats/summary接口：nodeIP:10255/stats/summary，heapster和最新的metrics-server从该接口获取数据

```yaml
      - job_name: 'cadvisor'
        # 通过https访问apiserver，通过apiserver的api获取数据
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token

        #以k8s的角色(role)来定义收集，比如node,service,pod,endpoints,ingress等等 
        kubernetes_sd_configs:
        # 从k8s的node对象获取数据
        - role: node

        relabel_configs:
        # 用新的前缀代替原label name前缀，没有replacement的话功能就是去掉label name前缀
        # 例如：以下两句的功能就是将__meta_kubernetes_node_label_kubernetes_io_hostname变为kubernetes_io_hostname
        - action: labelmap
          regex: __meta_kubernetes_node_label_(.+)

        # replacement中的值将会覆盖target_label中指定的label name的值,
        # 即__address__的值会被替换为kubernetes.default.svc:443
        - target_label: __address__
          replacement: kubernetes.default.svc:443

        # 获取__meta_kubernetes_node_name的值
        - source_labels: [__meta_kubernetes_node_name]
          #匹配一个或多个任意字符，将上述source_labels的值生成变量
          regex: (.+)
          # replacement中的值将会覆盖target_label中指定的label name的值,
          # 即__metrics_path__的值会被替换为/api/v1/nodes/${1}/proxy/metrics,
          # 其中${1}的值会被替换为__meta_kubernetes_node_name的值
          target_label: __metrics_path__
          replacement: /api/v1/nodes/${1}/proxy/metrics/cadvisor

        metric_relabel_configs:
          - action: replace
            source_labels: [id]
            regex: '^/machine\.slice/machine-rkt\\x2d([^\\]+)\\.+/([^/]+)\.service$'
            target_label: rkt_container_name
            replacement: '${2}-${1}'
          - action: replace
            source_labels: [id]
            regex: '^/system\.slice/(.+)\.service$'
            target_label: systemd_service_name
            replacement: '${1}'
```

## 8.5 应用实例

有的应用具有暴露容器内具体进程性能指标的需求，这些指标由应用侧实现暴露，并添加平台侧约定的annotations，平台侧可以根据约定的annotations实现Prometheus的scrape。

例如，应用侧为自己的service添加如下约定的annotation：

```
prometheus.io/scrape: 'true'
prometheus.io/app-metrics: 'true'
prometheus.io/app-metrics-port: '8080'
prometheus.io/app-metrics-path: '/metrics'1234
```

Prometheus可以：

- 根据`prometheus.io/scrape: 'true'`获知对应的endpoint是需要被scrape的
- 根据`prometheus.io/app-metrics: 'true'`获知对应的endpoint中有应用进程暴露的metrics
- 根据`prometheus.io/app-metrics-port: '8080'`获知进程暴露的metrics的端口号
- 根据`prometheus.io/app-metrics-path: '/metrics'`获知进程暴露的metrics的具体路径

除此之外可能还需要根据平台和业务的需求添加其他一些以`prometheus.io/app-info-`为前缀的annotation，以满足在平台对应用做其他一些标识的需求。比如加入如下annotation来标识应用所属的的环境、租户以及应用名称：

```
prometheus.io/app-info-env: 'test'
prometheus.io/app-info-tenant: 'test-tenant'
prometheus.io/app-info-name: 'test-app'123	
```

prometheus监控配置

```yaml
  - job_name: 'kubernetes-app-metrics'

        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token

        kubernetes_sd_configs:
        - role: endpoints
        relabel_configs:
        # 只保留endpoint中含有prometheus.io/scrape: 'true'的annotation的endpoint
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape, __meta_kubernetes_service_annotation_prometheus_io_app_metrics]
          regex: true;true
          action: keep
        # 将用户指定的进程的metrics_path替换默认的metrics_path
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_app_metrics_path]
          action: replace
          target_label: __metrics_path__
          regex: (.+)
        # 用pod_ip和用户指定的进程的metrics端口组合成真正的可以拿到数据的地址来替换原始__address__
        - source_labels: [__meta_kubernetes_pod_ip, __meta_kubernetes_service_annotation_prometheus_io_app_metrics_port]
          action: replace
          target_label: __address__
          regex: (.+);(.+)
          replacement: $1:$2
        # 去掉label name中的前缀__meta_kubernetes_service_annotation_prometheus_io_app_info_
        - action: labelmap
          regex: __meta_kubernetes_service_annotation_prometheus_io_app_info_(.+)
```

## 4.6 blackbox-exporter

[blackbox-exporter](https://github.com/prometheus/blackbox_exporter)是一个黑盒探测工具，可以对服务的http、tcp、icmp等进行网络探测。

- 部署

  ```yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    labels:
      app: prometheus-blackbox-exporter
    name: prometheus-blackbox-exporter
    namespace: kube-system
  data:
    blackbox.yml: |-
      modules:
        http_2xx:
          prober: http
          timeout: 10s
          http:
            valid_http_versions: ["HTTP/1.1", "HTTP/2"]
            valid_status_codes: []
            method: GET
            preferred_ip_protocol: "ip4"
        http_post_2xx: # http post 监测模块
          prober: http
          timeout: 10s
          http:
            valid_http_versions: ["HTTP/1.1", "HTTP/2"]
            method: POST
            preferred_ip_protocol: "ip4"
        tcp_connect:
          prober: tcp
          timeout: 10s
        icmp:
          prober: icmp
          timeout: 10s
          icmp:
            preferred_ip_protocol: "ip4"
  ---
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: prometheus-blackbox-exporter
    namespace: kube-system
  spec:
    selector:
      matchLabels:
        app: prometheus-blackbox-exporter
    replicas: 1
    template:
      metadata:
        labels:
          app: prometheus-blackbox-exporter
      spec:
        restartPolicy: Always
        containers:
        - name: prometheus-blackbox-exporter
          image: prom/blackbox-exporter:v0.12.0
          imagePullPolicy: IfNotPresent
          ports:
          - name: blackbox-port
            containerPort: 9115
          readinessProbe:
            tcpSocket:
              port: 9115
            initialDelaySeconds: 5
            timeoutSeconds: 5
          resources:
            requests:
              memory: 50Mi
              cpu: 100m
            limits:
              memory: 60Mi
              cpu: 200m
          volumeMounts:
          - name: config
            mountPath: /etc/blackbox_exporter
          args:
          - --config.file=/etc/blackbox_exporter/blackbox.yml
          - --log.level=debug
          - --web.listen-address=:9115
        volumes:
        - name: config
          configMap:
            name: prometheus-blackbox-exporter
        nodeSelector:
          node-role.kubernetes.io/master: "true"
        tolerations:
        - key: "node-role.kubernetes.io/master"
          effect: "NoSchedule"
  ---
  apiVersion: v1
  kind: Service
  metadata:
    labels:
      app: prometheus-blackbox-exporter
    name: prometheus-blackbox-exporter
    namespace: kube-system
    annotations:
      prometheus.io/scrape: 'true'
  spec:
    type: NodePort
    selector:
      app: prometheus-blackbox-exporter
    ports:
    - name: blackbox
      port: 9115
      targetPort: 9115
      nodePort: 30009
      protocol: TCP
  ```

  应用可以在service中指定平台侧约定的annotation，实现监控平台对该应用的网络服务进行探测：

  - http探测

    ```
    prometheus.io/scrape: 'true'
    prometheus.io/http-probe: 'true'
    prometheus.io/http-probe-port: '8080'
    prometheus.io/http-probe-path: '/healthz'1234
    ```

  - tcp探测

    ```
    prometheus.io/scrape: 'true'
    prometheus.io/tcp-probe: 'true'
    prometheus.io/tcp-probe-port: '80'123
    ```

  Prometheus根据这些annotation可以获知相应service是需要被探测的，探测的具体网络协议是http还是tcp或其他，以及具体的探测端口。http探测的话还要知道探测的具体url。

- Prometheus监控配置

  ```yaml
        - job_name: 'kubernetes-service-http-probe'
          tls_config:
            ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
          bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token

          kubernetes_sd_configs:
          - role: service

          # 将metrics_path由默认的/metrics改为/probe
          metrics_path: /probe

          # Optional HTTP URL parameters.
          # 生成__param_module="http_2xx"的label
          params:
            module: [http_2xx]

          relabel_configs:
          # 只保留含有label为prometheus/io=scrape的service
          - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape, __meta_kubernetes_service_annotation_prometheus_io_http_probe]
            regex: true;true
            action: keep
          - source_labels: [__meta_kubernetes_service_name, __meta_kubernetes_namespace, __meta_kubernetes_service_annotation_prometheus_io_http_probe_port, __meta_kubernetes_service_annotation_prometheus_io_http_probe_path]
            action: replace
            target_label: __param_target
            regex: (.+);(.+);(.+);(.+)
            replacement: $1.$2:$3$4

          # 用blackbox-exporter的service地址值”prometheus-blackbox-exporter:9115"替换原__address__的值
          - target_label: __address__
            replacement: prometheus-blackbox-exporter:9115
          - source_labels: [__param_target]
            target_label: instance
          # 去掉label name中的前缀__meta_kubernetes_service_annotation_prometheus_io_app_info_
          - action: labelmap
            regex: __meta_kubernetes_service_annotation_prometheus_io_app_info_(.+)

     ## kubernetes-services and kubernetes-ingresses are blackbox_exporter related

      # Example scrape config for probing services via the Blackbox Exporter.
      # 
      # The relabeling allows the actual service scrape endpoint to be configured
      # for all or only some services.
      - job_name: 'kubernetes-service-tcp-probe'

        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token

        kubernetes_sd_configs:
        - role: service

        # 将metrics_path由默认的/metrics改为/probe
        metrics_path: /probe

        # Optional HTTP URL parameters.
        # 生成__param_module="tcp_connect"的label
        params:
          module: [tcp_connect]

        relabel_configs:
        # 只保留含有label为prometheus/io=scrape的service
        - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape, __meta_kubernetes_service_annotation_prometheus_io_tcp_probe]
          regex: true;true
          action: keep
        - source_labels: [__meta_kubernetes_service_name, __meta_kubernetes_namespace, __meta_kubernetes_service_annotation_prometheus_io_tcp_probe_port]
          action: replace
          target_label: __param_target
          regex: (.+);(.+);(.+)
          replacement: $1.$2:$3
        # 用blackbox-exporter的service地址值”prometheus-blackbox-exporter:9115"替换原__address__的值
        - target_label: __address__
          replacement: prometheus-blackbox-exporter:9115
        - source_labels: [__param_target]
          target_label: instance
        # 去掉label name中的前缀__meta_kubernetes_service_annotation_prometheus_io_app_info_
        - action: labelmap
          regex: __meta_kubernetes_service_annotation_prometheus_io_app_info_(.+)
  ```


# 5. prometheus部署

- pull image
  ```
  # docker pull prom/node-exporter
  # docker pull prom/blackbox-exporter
  # docker pull prom/prometheus:v2.0.0
  # docker pull grafana/grafana:4.2.0
  ```

- node-exporter

- prometheus

- grafana


#6. Prometheus Operator

为了在Kubernetes能够方便的管理和部署Prometheus，使用ConfigMap了管理Prometheus配置文件。每次对Prometheus配置文件进行升级时，需要手动移除已经运行的Pod实例，从而让Kubernetes可以使用最新的配置文件创建Prometheus。 而如果当应用实例的数量更多时，通过手动的方式部署和升级Prometheus过程繁琐并且效率低下。

为了能够自动化的处理这些复杂操作，CoreOS引入了Opterator。简单来说，Opterator就是通过扩展Kubernetes API，帮助用户部署，配置和管理复杂的有状态应用程序示例，通过软件定义的方式来管理运维操作。

## 6.1 架构

Prometheus Operator建立在Kubernetes的资源以及控制器的概念之上，通过在Kubernetes中添加自定义资源类型，通过声明式的方式，Operator可以自动部署和管理Prometheus实例的运行状态，并且根据监控目标管理并重新加载Prometheus的配置文件，大大简化Prometheus这类有状态应用运维管理的复杂度。

![prometheusOP-architecture.png](./Picture/prometheusOP-architecture.png)

为了能够通过声明式的对Prometheus进行自动化管理。Prometheus Operator通过自定义资源类型的方式定义了一下3个主要自定义资源类型：

- Prometheus

自定义资源`Prometheus`中声明式的定义了在Kubernetes集群中所需运行的Prometheus的设置。如下所示：

  ```
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  name: prometheus
spec:
  serviceMonitorSelector:
    matchLabels:
      team: frontend
  resources:
    requests:
      memory: 400Mi
  ```

在该Yaml中我们可以定义Prometheus实例所使用的资源，以及需要关联的ServiceMonitor等。除此以外，还可以定义如Replica，Storage，以及关联的Alertmanager实例等信息。

- ServiceMonitor

通过自定义资源类型`ServiceMonitor`用户可以通过声明式的方式定义需要监控集群中的哪些资源。如下所示：

```
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: example-app
  labels:
    team: frontend
spec:
  selector:
    matchLabels:
      app: example-app
  endpoints:
  - port: web
```
- Alertmanager

通过自定义资源类型`Alertmanager`，用户可以声明式的定义在Kubernetes集群中所需要运行的Alertmanager信息，如下所示：

```
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata:
  name: example
spec:
  replicas: 3
```

```

```
