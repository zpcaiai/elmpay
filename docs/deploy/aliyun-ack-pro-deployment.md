# 阿里云 ACK Pro 部署配置与实施文档（生产版）

更新时间：2026-09-14  
适用范围：`/Users/stephen/Documents/Projects/python/elmpay`

## 1. 目标与边界

本文件给出 **阿里云 ACK 托管集群（Managed Kubernetes Pro）** 的部署配置与实施步骤，目标是建立可上线的生产基础设施，并与项目现有交付/复审链路衔接。

- 目标场景：**国内 MVP 先行**，默认上海主站（`cn-shanghai`）。
- 交付优先级：
  1. 集群与网络/安全基线
  2. 应用部署与外部入口（Ingress）
  3. 可观测、告警与日志
  4. 滚动发布与回滚机制
- 说明：外部认证（Provider 认证、PCI/UAT/独立评审/渗透测试等）仍为外部门禁，不可由本地文档代替提交，当前认证状态不因此改变。

## 2. 参考入口（官方）

- ACK 概览（Managed Pro 功能、SLA）：  
  https://help.aliyun.com/en/ack/ack-managed-and-ack-dedicated/user-guide/ack-cluster-overview/
- ACK 托管集群创建（控制台/API/Terraform/CLI）：  
  https://help.aliyun.com/en/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster-2/
- ACK Managed 组件：  
  https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/component-overview
- ALB Ingress：  
  https://www.alibabacloud.com/help/en/ack/distributed-cloud-container-platform-for-kubernetes/user-guide/alb-ingress-overview
- ACK 自动托管模式（Auto Mode）：  
  https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/create-ack-managed-clusters-in-auto-mode

## 3. 环境与权限前置

1. 确认账号已激活：
   - ACK
   - VPC
   - SLB/CLB
   - NAT Gateway（若集群需要访问外网）
2. RAM 权限：
   - 开通 ACK 需要的系统服务角色
   - 对应 ECS/VPC/SLB 资源的管理权限
3. 账户余额满足按量资源（CLB/EIP/ECS）开通要求。
4. 准备：
   - 域名与证书
   - 镜像仓库凭据（ACR/私有仓库）
   - 监控与告警接收联系人
   - 备份存储（SLS/OSS 或对象存储）

## 4. 网络与安全规划（MVP 示例）

- Region：`cn-shanghai`
- 可用区：`cn-shanghai-a` + `cn-shanghai-b`（最少双AZ）
- VPC CIDR：`10.0.0.0/16`
- Worker 子网：`10.0.1.0/24`, `10.0.2.0/24`
- Service CIDR：`172.21.0.0/16`
- Network 插件：`Terway`（推荐）
- API Server：`endpoint_public_access: false`（先闭内网）
- SNAT：如需拉取公网镜像或访问外网服务，打开 `snat_entry: true`
- Deletion Protection：`true`
- 安全组原则：
  - 仅放行业务需要端口
  - 对内网组件与数据库使用白名单
  - 如使用现有 SG，需补齐 100.64.0.0/10 等必要放行规则

## 5. 集群参数清单（可复制）

### 5.1 关键字段

| 类别 | 字段 | 建议值 |
|---|---|---|
| 集群类型 | `cluster_type` | `ManagedKubernetes` |
| 集群子类型 | `profile` | `Default` |
| 规格 | `cluster_spec` | `ack.pro.small` |
| 版本 | `kubernetes_version` | 按当前可用最新版本 |
| 容器运行时 | `kubernetes_config.runtime` | `containerd` |
| 运维 | `deletion_protection` | `true` |
| 可达性 | `endpoint_public_access` | `false`（内网优先） |
| 节点池 | `multi_az_policy` | `BALANCE` |

### 5.2 API 请求示例（示例值）

```json
{
  "name": "elmpay-sh-prod",
  "cluster_type": "ManagedKubernetes",
  "profile": "Default",
  "cluster_spec": "ack.pro.small",
  "kubernetes_version": "1.32.1-aliyun.1",
  "region_id": "cn-shanghai",
  "snat_entry": true,
  "endpoint_public_access": false,
  "deletion_protection": true,
  "proxy_mode": "ipvs",
  "vpcid": "vpc-xxxxxxxx",
  "vswitch_ids": ["vsw-xxxxxxxxa", "vsw-xxxxxxxxb"],
  "pod_vswitch_ids": ["vsw-pod-xxxxxxa", "vsw-pod-xxxxxxb"],
  "service_cidr": "172.21.0.0/16",
  "ip_stack": "ipv4",
  "os_type": "Linux",
  "platform": "AliyunLinux",
  "image_type": "AliyunLinux3",
  "addons": [
    { "name": "terway-controlplane", "config": "{\"ENITrunking\":\"true\"}" },
    { "name": "terway-eniip", "config": "{\"IPVlan\":\"false\",\"NetworkPolicy\":\"false\",\"ENITrunking\":\"true\"}" },
    { "name": "csi-plugin" },
    { "name": "managed-csiprovisioner" },
    { "name": "storage-operator" },
    { "name": "logtail-ds" },
    { "name": "ack-node-local-dns" },
    { "name": "metrics-server" }
  ],
  "nodepools": [
    {
      "nodepool_info": { "name": "default-nodepool" },
      "scaling_group": {
        "system_disk_category": "cloud_essd",
        "system_disk_size": 120,
        "system_disk_performance_level": "PL0",
        "instance_types": ["ecs.c6.xlarge"],
        "instance_charge_type": "PostPaid",
        "desired_size": 3,
        "security_group_ids": [],
        "vswitch_ids": ["vsw-xxxxxxxxa", "vsw-xxxxxxxxb"],
        "multi_az_policy": "BALANCE"
      },
      "kubernetes_config": {
        "cpu_policy": "none",
        "runtime": "containerd",
        "runtime_version": "1.6.36"
      },
      "management": {
        "enable": true,
        "auto_repair": true,
        "auto_repair_policy": { "restart_node": true },
        "auto_upgrade": true,
        "auto_upgrade_policy": {
          "auto_upgrade_kubelet": true,
          "auto_upgrade_os": false
        },
        "auto_vul_fix": true,
        "auto_vul_fix_policy": { "vul_level": "asap", "restart_node": true },
        "rolling_policy": { "max_parallelism": 10 }
      }
    }
  ]
}
```

> 注意：以上示例仅示意。`vpcid`、`vsw-...` 等字段必须替换为你当前账号真实 ID。

## 6. 控制台创建步骤（推荐）

1. 登录 ACK Console → `Clusters` → `Create Cluster`
2. 创建类型选择 `ManagedKubernetes`
3. Edition 选择 `Pro`
4. 配置：
   - 集群：版本、名称、Zone、SNAT、API Server 访问
   - 网络：Terway、Service CIDR、vSwitch、Pod vSwitch
   - NodePool：镜像/实例/系统盘/计费
   - Components：按 5.2 选择基础组件
5. 确认费用并提交创建

## 7. 接入与部署（最小可用）

### 7.1 kubeconfig 与连通性

1. 下载 kubeconfig
2. 执行：

```bash
kubectl get nodes
kubectl get ns
kubectl get pods -A
```

### 7.2 命名空间与部署模板（可先用于 smoke）

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: elmpay
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elmpay-api
  namespace: elmpay
spec:
  replicas: 3
  selector:
    matchLabels:
      app: elmpay-api
  template:
    metadata:
      labels:
        app: elmpay-api
    spec:
      containers:
      - name: api
        image: registry.cn-shanghai.aliyuncs.com/your-team/elmpay-api:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 20
          periodSeconds: 10
        resources:
          requests:
            cpu: "200m"
            memory: "256Mi"
          limits:
            cpu: "1000m"
            memory: "1Gi"
---
apiVersion: v1
kind: Service
metadata:
  name: elmpay-api
  namespace: elmpay
spec:
  selector:
    app: elmpay-api
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elmpay-api
  namespace: elmpay
  annotations:
    kubernetes.io/ingress.class: "alb"
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/scheme: internet-facing
spec:
  tls:
  - hosts:
    - pay.example.com
    secretName: elmpay-tls
  rules:
  - host: pay.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: elmpay-api
            port:
              number: 80
```

## 8. 发布与回滚

- 发布策略：Rolling Update + readiness gate
- 回滚：
  - Deployment 回滚：`kubectl rollout undo deployment/elmpay-api -n elmpay`
  - 失败时先缩容高风险副本，核对 readiness 与 DB 连接后再继续滚动
- 建议增加：
  - PDB（`minAvailable: 2`）
  - HPA（按 CPU/Memory）
  - Prometheus/告警（错误率、P99、支付超时、外部回调耗时）

## 9. 与 DR 一致性（后续扩展）

当前优先：上海主站单区域上线。  
阶段二：按需补齐北京灾备环境，并按以下顺序演练：

1. 镜像与配置同步
2. 灾备环境 dry run 部署
3. DNS/流量切换演练（定期）
4. 回切验证
5. 业务层回退演练（可观测告警闭环）

## 10. 变更记录模板（可直接复制）

```md
## 变更项
- 项目：elmpay ACK Pro 部署
- 变更时间：YYYY-MM-DD
- 集群 ID：<cluster-id>
- 环境：cn-shanghai
- 变更人：
- 变更内容：
  - ...
- 验证命令：
  - kubectl get nodes
  - kubectl get ingress -A
  - kubectl get pods -A
  - curl -k https://pay.example.com/healthz
- 回退方案：
  - ...
```

---

如需，我下一步可继续把上面文档再拆成“上海单区域执行清单版（含具体命令）+ 北京 DR 扩展版 + 变更窗口审批模板”，并与现有 `docs` 命名规范自动对齐。
