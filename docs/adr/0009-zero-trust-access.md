# ADR-0009: 零信任：服务 mTLS、管理员 WebAuthn、RBAC/ABAC/SoD

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-security
- 关联需求：PAY-REQ-0041, PAY-REQ-0042, PAY-REQ-0040
- 关联控制：NN-11, CTRL-004, CTRL-014
- 取代：无

## 背景

内网可信假设在被攻陷终端、供应链攻击与横向移动面前失效；支付后台是资金与数据的最高价值目标，短信/TOTP 均可被钓鱼。

## 决策

服务间通信强制 mTLS 与网络策略；管理后台强制 WebAuthn/硬件密钥并对高风险操作 step-up；权限采用 RBAC+ABAC、职责分离与临时授权，定期访问复核。

## 后果

运维复杂度上升（证书生命周期、密钥注册）；换来的是钓鱼与凭证窃取不足以直接拿到资金权限。

## 备选方案

（a）VPN + 密码：拒绝，可钓鱼且无职责分离；（b）仅 TOTP：拒绝，可实时中继钓鱼。

## 验证

`test_b00_project_config.py` 强制 `admin_mfa=webauthn_required`；B17-B19、B89。
