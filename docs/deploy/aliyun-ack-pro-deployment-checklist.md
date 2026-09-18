# ACK Pro 国内 MVP（一站式）部署执行清单（可直接照跑）

适用场景：`elmpay` 国内上线（先到生产，默认上海主站），
并与当前仓库已有的生产 Kubernetes/DR/认证治理边界衔接。

> 说明：本清单只覆盖 **代码/基础设施层**；Provider 官方认证、PCI、独立评审、UAT、渗透、商户验收、生产 Rollout 仍为外部门禁，不会被本地命令替代。

## 0. 目标结果（本次会产出）
- `kubectl` 与 ACK 集群连通（Master 与 Node 可见）
- 生成并审核以下三类部署清单文件：
  - `docs/deploy/aliyun-ack-pro-rendered/workloads.yaml`
  - `docs/deploy/aliyun-ack-pro-rendered/service-controls.yaml`
  - `docs/deploy/aliyun-ack-pro-rendered/egress-controls.yaml`
- 对生产命名空间执行滚动发布
- 完成健康探测与基础回滚演练
- 不修改 `0/128 NOT_CERTIFIED` 声明

## 1. 前置准备（人眼确认）
```bash
cd /Users/stephen/Documents/Projects/python/elmpay
git checkout main
git pull --ff-only origin main
git status --short
python3 -V
kubectl version --client
helm version
aliyun version
```
检查点：
- 当前分支 `main` 且工作区干净（预期外更改清楚记录）
- `main` 与远端一致

## 2. 建议目录与文件约定
```bash
mkdir -p docs/deploy/aliyun-ack-pro-rendered
mkdir -p evidence/external
```

> 下面命令中的 `<...>` 为占位符，需要按真实部署环境替换。

## 3. ACK 集群创建与连接（上海主站）

### 3.1 控制台创建（推荐）
在阿里云 ACK 控制台按以下参数创建：
- 集群类型：`Managed Kubernetes (Pro)`
- 地域：`cn-shanghai`
- 集群名：`elmpay-sh-prod`
- Pod/Service CIDR：`172.21.0.0/16`
- Worker 子网至少 2 个可用区：`cn-shanghai-a,b`
- Pod 网路模型：`Terway`
- 容器运行时：`containerd`
- `public apiServer`：禁用（`false`）以内网优先
- `SNAT`：如需拉公网镜像需开启

### 3.2 命令行创建（如使用 CLI）
```bash
aliyun configure
aliyun cs DescribeClusters --RegionId cn-shanghai
# 用你组织内标准参数创建，关键字段见模板文档：docs/deploy/aliyun-ack-pro-templates.md
```

### 3.3 下载 kubeconfig 并连通
```bash
aliyun cs DescribeClusterKubeconfig \
  --ClusterId <ACK_CLUSTER_ID> \
  --PrivateIpAddress false \
  --OutputFile /tmp/elmpay-sh-prod-kubeconfig
export KUBECONFIG=/tmp/elmpay-sh-prod-kubeconfig
kubectl get nodes
kubectl cluster-info
```

## 4. 产物准备（镜像与签名可追溯）
```bash
# 1) 准备映像集合（示例：可从CI的 product image index 生成）
cat > /tmp/elmpay-workload-images.json <<'EOF'
{
  "edge-gateway": "ghcr.io/<org>/elmpay-edge-gateway@sha256:<digest>",
  "checkout-web": "ghcr.io/<org>/elmpay-checkout-web@sha256:<digest>",
  "admin-web": "ghcr.io/<org>/elmpay-admin-web@sha256:<digest>",
  "risk-engine": "ghcr.io/<org>/elmpay-risk-engine@sha256:<digest>",
  "worker-scheduler": "ghcr.io/<org>/elmpay-worker-scheduler@sha256:<digest>",
  "webhook-processor": "ghcr.io/<org>/elmpay-webhook-processor@sha256:<digest>"
}
EOF
```

### 4.1 渲染工作负载（严格 digest）
```bash
python3 tools/runtime/control.py render-kubernetes \
  --images /tmp/elmpay-workload-images.json \
  --policy platform/kubernetes/workload-policy.json \
  > docs/deploy/aliyun-ack-pro-rendered/workloads.yaml

python3 tools/platform_control.py render-service-controls \
  --workloads platform/kubernetes/workload-policy.json \
  --callers platform/kubernetes/service-callers.json \
  > docs/deploy/aliyun-ack-pro-rendered/service-controls.yaml

python3 tools/render_egress_policy.py \
  --workload-policy platform/kubernetes/workload-policy.json \
  --egress-policy platform/kubernetes/egress-policy.json \
  > docs/deploy/aliyun-ack-pro-rendered/egress-controls.yaml

python3 tools/platform_control.py render-data-plane \
  --policy platform/kubernetes/data-plane-policy.json \
  > docs/deploy/aliyun-ack-pro-rendered/data-plane.yaml
```

检查点：
- 三个 `render-*` 命令成功且未报 `immutable digest` 或 `missing service` 错误
- 文件非空，且 `workloads.yaml` 为可应用对象列表

## 5. 生产配置落地（按顺序执行）
> 假设 ALB/Istio/Cilium 等 CRD 已在集群中安装（若未安装先完成对应依赖安装）

```bash
kubectl create namespace elmpay || true
kubectl apply -f docs/deploy/aliyun-ack-pro-rendered/service-controls.yaml
kubectl apply -f docs/deploy/aliyun-ack-pro-rendered/egress-controls.yaml
kubectl apply -f docs/deploy/aliyun-ack-pro-rendered/data-plane.yaml
kubectl apply -f docs/deploy/aliyun-ack-pro-rendered/workloads.yaml
```

### 5.1 配置证书与 Ingress（按你们域名绑定）
```bash
kubectl create secret generic elmpay-tls \
  --namespace elmpay \
  --from-file=tls.crt=./tls/your-domain.crt \
  --from-file=tls.key=./tls/your-domain.key \
  --dry-run=client -o yaml | kubectl apply -f -

# 将模板参数化对象导出为真实 manifest 后再 apply（namespace/secret可在模板内按需定义）：
cat > /tmp/elmpay-gateway.yaml <<EOF
# 由 docs/deploy/aliyun-ack-pro-templates.md 中参数替换后贴入的真实 YAML
EOF
# kubectl apply -f /tmp/elmpay-gateway.yaml
```
> 生产北南向入口（ALB/网关）与 TLS/SNI 以模板文档中的参数化清单为准；模板不直接下发真实 secret，需提前在集群中创建 TLS Secret。

## 6. 验收与监控
```bash
kubectl get ns elmpay
kubectl get pods -n elmpay -o wide
kubectl get deployments,pods,hpa,pdb,svc -n elmpay
kubectl get ingress -A
kubectl top nodes
kubectl top pods -A

kubectl -n elmpay rollout status deployment/edge-gateway
kubectl -n elmpay rollout status deployment/risk-engine
kubectl -n elmpay rollout status deployment/checkout-web
kubectl -n elmpay rollout status deployment/admin-web
```
健康检查（与目标域名替换）：
```bash
curl -skI https://pay.example.com/healthz
curl -sk https://pay.example.com/healthz
```

## 7. 灰度与回滚（最低要求）
```bash
kubectl -n elmpay rollout history deployment/edge-gateway
kubectl -n elmpay rollout undo deployment/edge-gateway --to-revision=1
kubectl -n elmpay scale deployment/edge-gateway --replicas=0
kubectl -n elmpay scale deployment/edge-gateway --replicas=3
```
执行要求：
- 任何回滚动作有命令记录和时间点
- 回滚前先确认 `kubectl logs` 与 `kubectl get events -n elmpay --sort-by=.metadata.creationTimestamp`

## 8. 交付痕迹（最小）
保存以下文件（与外部证据分离）：
- `docs/deploy/aliyun-ack-pro-rendered/workloads.yaml`
- `docs/deploy/aliyun-ack-pro-rendered/service-controls.yaml`
- `docs/deploy/aliyun-ack-pro-rendered/egress-controls.yaml`
- `docs/deploy/aliyun-ack-pro-rendered/data-plane.yaml`
- `kubectl` 日志与回滚记录（贴到 release 记录里）

## 9. 完成判断（本阶段）
- 所有服务 `READY > 0`，`CrashLoopBackOff` 为 `0`
- 关键路径可达（健康探针 OK）
- 基本 HPA、PDB、Service、Namespace/SA、NetworkPolicy 已落地
- 未宣称 B00/B01+ 认证通过；保持 `0/128 NOT_CERTIFIED`，待外部证据链接入后再进入正式 rebaseline
