
# 继续下一批次

运行 `python3 .payment-platform/skill-package/scripts/orchestrate.py ready --repo .`，对所有 ready 批次生成 prompt。先核验现有完成文件与实际代码、测试和运行证据一致，再分派对应 skill。完成后逐批运行 validate；不要一次伪造多个 completion 文件。
