# syntax=docker/dockerfile:1-labs
FROM ubuntu:24.04

RUN mkdir -p /opt/windows

WORKDIR /opt/windows
COPY windows/Autounattend.xml windows/setup.ps1 windows/config_startup.ps1 windows/sshd_config ./
COPY windows/shutdown.py .

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && xargs apt-get install --no-install-recommends -yqq <<EOF && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
        apt-transport-https
        ca-certificates
        curl
        dosfstools
        mtools
        openssh-client
        python3
        qemu-kvm
        qemu-utils
        xorriso
        netcat-openbsd
EOF

RUN <<EOF
    sed -i "s/INSTALL_IDA_FREE/${INSTALL_IDA_FREE}/g" ./setup.ps1
    mkdir -p ./build
    mkfs.fat -F 12 -C ./build/floppy.img 1440
    mcopy -si ./build/floppy.img ./Autounattend.xml ./setup.ps1 ./config_startup.ps1 ./sshd_config ::
    rm -rf ./Autounattend.xml ./setup.ps1 ./config_startup.ps1 ./sshd_config

    echo "Building virtio drivers disk"
    curl -Lo virtio-win-raw.iso \
      'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso'
    WORKDIR="$(mktemp -d --suffix=.img-extract)"
    EXTRACT_DIR="$WORKDIR/virtio-win"
    mkdir -p "$EXTRACT_DIR"
    xorriso -report_about SORRY -osirrox on -indev ./virtio-win-raw.iso -extract / "$EXTRACT_DIR"
    rm ./virtio-win-raw.iso
    xorriso \
      -as genisoimage -rock -joliet -volid VIRTIO \
      -output ./build/virtio-win-processed.iso \
      "$WORKDIR"
    rm -rf "$WORKDIR" virtio-win-raw.iso

    echo "Downloading Windows Server ISO"
    curl -Lo ./build/server-2022.iso \
      'https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso'
EOF

RUN --security=insecure <<EOF
    echo "Creating VM image"
    rm -rf ./build/clean.qcow2 ./build/image-built
    qemu-img create -f qcow2 ./build/clean.qcow2 51200M
    echo "Installing and configuring windows (this will take 20+ min)"
    qemu-system-x86_64 \
      -name dojo \
      -boot once=d \
      -machine type=pc,accel=kvm \
      -m 4096M \
      -smp "$(nproc)" \
      -display vnc=:12 \
      -nographic \
      -device virtio-net,netdev=user.0 \
      -netdev user,id=user.0,hostfwd=tcp::5985-:5985,hostfwd=tcp::2222-:22 \
      -serial null \
      -drive "file=./build/floppy.img,format=raw,index=0,if=floppy" \
      -drive "file=./build/server-2022.iso,media=cdrom" \
      -drive "file=./build/virtio-win-processed.iso,media=cdrom" \
      -drive "file=./build/clean.qcow2,if=virtio,cache=writeback,discard=ignore,format=qcow2"
    rm -rf ./build/monitor.sock
EOF

COPY windows/challenge-proxy.c windows/post_install.sh windows/post_install.ps1 windows/startup.ps1 ./

RUN --security=insecure <<EOF
    echo "Performing initial bootup"
    qemu-system-x86_64 \
      -name dojo \
      -boot once=d \
      -machine type=pc,accel=kvm \
      -m 4096M \
      -smp "$(nproc)" \
      -display vnc=:12 \
      -nographic \
      -device virtio-net,netdev=user.0 \
      -netdev user,id=user.0,hostfwd=tcp::5985-:5985,hostfwd=tcp::2222-:22 \
      -serial null \
      -drive "file=./build/floppy.img,format=raw,index=0,if=floppy" \
      -drive "file=./build/server-2022.iso,media=cdrom" \
      -drive "file=./build/virtio-win-processed.iso,media=cdrom" \
      -drive "file=./build/clean.qcow2,if=virtio,cache=writeback,discard=ignore,format=qcow2" &
    ./post_install.sh
    rm -f ./build/monitor.sock
EOF
