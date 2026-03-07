FROM debian:bookworm-slim

# Install all build dependencies
RUN apt-get update && apt-get install -y \
    qemu-user-static \
    binfmt-support \
    kpartx \
    parted \
    e2fsprogs \
    dosfstools \
    rsync \
    xz-utils \
    wget \
    curl \
    mount \
    udev \
    && rm -rf /var/lib/apt/lists/*

# Ensure binfmt is registered
RUN update-binfmts --enable qemu-aarch64 2>/dev/null || true && \
    update-binfmts --enable qemu-arm 2>/dev/null || true

WORKDIR /build

ENTRYPOINT ["/build/image/build.sh"]
