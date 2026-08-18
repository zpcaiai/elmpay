# GENERATED FILE — do not edit by hand.
# Source of truth: governance/dev-platform.json
# Regenerate with: python3 scripts/render-dev-platform.py

# Offline wechat simulator. Standard library only, no package index needed.
FROM python:3.12.7-slim

WORKDIR /app
COPY tools/simulator /app/tools/simulator
ENV PYTHONPATH=/app
USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["python3", "-m", "tools.simulator.provider_sim", "--provider", "wechat"]
