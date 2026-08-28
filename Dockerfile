# te-runner: the one image every TE 2.0 lab container/VM references, built only in CI.
# Per-instance state baked into a shared image caused three v1 incidents (te-labkit-v2/PRD.md
# rock 2); building from scratch each tag makes that class hard to recreate.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git jq unzip less groff \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (arch-aware; pinning happens via the image tag, not here)
RUN ARCH=$(uname -m) && \
    curl -sSf "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscli.zip && \
    unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install && rm -rf /tmp/aws /tmp/awscli.zip

COPY wizlab/wizlab /usr/local/bin/wizlab
COPY measurements.yaml /opt/te/measurements.yaml
RUN chmod 755 /usr/local/bin/wizlab

CMD ["sleep", "infinity"]
