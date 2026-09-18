# ACK Pro + Kubernetes 部署模板（参数化版）

> 该文档用于提交变更或交由平台组套模版化落地。  
> 模板中的 `${...}` 为必填变量，落地时必须替换为真实值。

## 1) ACK Pro 集群参数模板（概念层）

```json
{
  "cluster": {
    "name": "elmpay-sh-prod",
    "region": "cn-shanghai",
    "cluster_type": "ManagedKubernetes",
    "version_profile": "ack-pro",
    "kubernetes_version": "1.32.1-aliyun.1",
    "vpc_id": "${VPC_ID}",
    "vswitch_ids": ["${VSWITCH_ID_A}", "${VSWITCH_ID_B}"],
    "pod_vswitch_ids": ["${POD_VSWITCH_ID_A}", "${POD_VSWITCH_ID_B}"],
    "service_cidr": "172.21.0.0/16",
    "endpoint_public_access": false,
    "snat_entry": true,
    "deletion_protection": true,
    "node_pool": {
      "name": "elmpay-prod",
      "instance_type": "ecs.c6.xlarge",
      "instance_count": 3,
      "system_disk_category": "cloud_essd",
      "system_disk_size_gib": 120,
      "system_disk_performance_level": "PL0",
      "runtime": "containerd",
      "runtime_version": "1.6.36",
      "security_group_ids": ["${SECURITY_GROUP_ID}"]
    },
    "addons": [
      "terway-controlplane",
      "terway-eniip",
      "csi-plugin",
      "managed-csiprovisioner",
      "storage-operator",
      "logtail-ds",
      "ack-node-local-dns",
      "metrics-server"
    ]
  }
}
```

## 2) Terraform 样板（可直接转换成环境配置）

```hcl
resource "alicloud_cs_managed_kubernetes" "elmpay_sh_prod" {
  name                   = "elmpay-sh-prod"
  cluster_spec           = "ack.pro.small"
  version                = "1.32.1-aliyun.1"
  cluster_type           = "ManagedKubernetes"
  deletion_protection    = true
  vswitch_ids            = [var.vsw_a, var.vsw_b]
  pod_vswitch_ids        = [var.pod_vsw_a, var.pod_vsw_b]
  service_cidr           = "172.21.0.0/16"
  endpoint_public_access = false
  slb_internet_enabled   = false
  config {
    labels {
      type      = "key"
      value     = "elmpay-production"
      key       = "environment"
      auto_mode = false
    }
  }
  runtime {
    runtime_name = "containerd"
  }
}

resource "alicloud_cs_kubernetes_node_pool" "elmpay_prod" {
  cluster_id              = alicloud_cs_managed_kubernetes.elmpay_sh_prod.id
  name                    = "elmpay-prod"
  instance_types          = ["ecs.c6.xlarge"]
  desired_size            = 3
  system_disk_category    = "cloud_essd"
  system_disk_size        = 120
  security_group_ids      = [var.security_group]
  vswitch_ids             = [var.vsw_a, var.vsw_b]
  spot_strategy           = "NoSpot"
  password                = random_password.k8s_node.result
  kubernetes_config {
    runtime_version = "1.6.36"
  }
}
```

> 实际字段请以当前阿里云控制台/Terraform Provider 当前版本为准，`spot_strategy` 仅作示例，生产应按成本/可用性策略确认。

## 3) 命名空间与镜像拉取凭据模板（可直接落地）

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: elmpay
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: baseline
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: edge-gateway
  namespace: elmpay
---
apiVersion: v1
kind: Secret
metadata:
  name: elmpay-image-pull
  namespace: elmpay
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ${BASE64_DOCKER_CONFIG_JSON}
---
apiVersion: v1
kind: Secret
metadata:
  name: elmpay-tls
  namespace: elmpay
type: kubernetes.io/tls
data:
  tls.crt: ${BASE64_TLS_CERT}
  tls.key: ${BASE64_TLS_KEY}
```

## 4) 北向入口与路由（示例）

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: elmpay-public
  namespace: elmpay
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/certificate-id: ${ALB_CERTIFICATE_ID}
spec:
  tls:
    - hosts:
      - ${PUBLIC_DOMAIN}
      secretName: elmpay-tls
  rules:
  - host: ${PUBLIC_DOMAIN}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: checkout-web
            port:
              number: 80
```

> 本文件为模板，不是可直接生产 apply 的单一对象。  
> 生产 north-south 入口通常还包含：
> - 管理端域名（admin）
> - 仅对 `edge-gateway` 的 mTLS/网关鉴权入口
> - 与 Istio Gateway/VirtualService 一致的 host/path/权重配置

## 5) 灰度/回滚参数（可复制）

```yaml
deploy:
  canary:
    enabled: true
    initialPercent: 5
    maxPercent: 30
    stepPercent: 5
    intervalSeconds: 120
  rollback:
    enabled: true
    onError:
      - UnreadyReplica=5m
      - ErrorRate>1%
      - Http5xx>0.3%
```

## 6) 备案产出清单（建议交接）
- ACK 集群 ID：`${ACK_CLUSTER_ID}`
- API Server Endpoint（内网）
- VPC/VSwitch/SG/SLB 关键信息
- 镜像 digest 清单（六服务全部）
- 上线时间窗口与审批人
- 回归验证命令与结果快照（含回滚命令执行记录）
- 变更单号（工单号）
