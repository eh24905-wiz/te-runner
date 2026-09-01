# te-runner: the one image every TE 2.0 lab container/VM references, built only in CI.
# Per-instance state baked into a shared image caused three v1 incidents (te-labkit-v2/PRD.md
# rock 2); building from scratch each tag makes that class hard to recreate.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git jq unzip less groff openssh-server tmux \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (arch-aware; pinning happens via the image tag, not here)
RUN ARCH=$(uname -m) && \
    curl -sSf "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscli.zip && \
    unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install && rm -rf /tmp/aws /tmp/awscli.zip

# Terraform: labs stage CSP infra from a runner container (the native terraform resource has no
# egress — te-labkit-v2 lab-patterns). Pinned; version bumps via a new image tag. HashiCorp names
# archives amd64/arm64, so dpkg --print-architecture (not uname -m, which the AWS CLI uses).
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSfL "https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_${ARCH}.zip" -o /tmp/tf.zip && \
    unzip -q /tmp/tf.zip -d /usr/local/bin && rm /tmp/tf.zip

# gcloud + az: native CSP CLIs alongside the AWS one (unpinned like it — the image tag is the pin).
# gcloud from Google's apt repo; az via pip because Microsoft's apt repo trails new Debian codenames
# and this image's python is the stable interpreter. Entrypoint logs both in from the injected env.
RUN curl -sSf https://packages.cloud.google.com/apt/doc/apt-key.gpg -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && apt-get install -y --no-install-recommends google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir azure-cli

# Tailscale static binaries (dev-only mesh; entrypoint starts it only when TS_AUTHKEY is injected on
# a dev track). Pinned; bump via a new image tag. tgz names amd64/arm64 → dpkg --print-architecture.
RUN ARCH=$(dpkg --print-architecture) && TSVER=1.102.3 && \
    curl -sSfL "https://pkgs.tailscale.com/stable/tailscale_${TSVER}_${ARCH}.tgz" -o /tmp/ts.tgz && \
    tar -xzf /tmp/ts.tgz -C /tmp && \
    mv "/tmp/tailscale_${TSVER}_${ARCH}/tailscale" "/tmp/tailscale_${TSVER}_${ARCH}/tailscaled" /usr/local/bin/ && \
    rm -rf /tmp/ts.tgz "/tmp/tailscale_${TSVER}_${ARCH}"

COPY wizlab/wizlab /usr/local/bin/wizlab
COPY measurements.yaml /opt/te/measurements.yaml
COPY reaper/reap_orphans.py /opt/reaper/reap_orphans.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/wizlab /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
