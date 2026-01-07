# Custom Target Images

Follow these steps to run Leash against a container image you control.

## Compatibility Requirements

- Kernel: 5.7+ (LSM BPF hooks)
- update-ca-certificates

Install `update-ca-certificates` via your distro's package manager if it's missing:

```sh
# Debian / Ubuntu
apt-get update && apt-get install -y ca-certificates

# Rocky Linux
dnf install -y ca-certificates

# Alpine Linux
apk add --no-cache ca-certificates
```

*Note: Rootless containers typically lack required privileges for BPF*

### Verification

- `uname -r` to check version
- Confirm your distro’s kernel enables BPF and LSM BPF (most modern distros do)

## 1. Update your Dockerfile

```Dockerfile
FROM public.ecr.aws/s5i7k8t3/strongdm/leash:latest AS leash

# ... your existing build stages ...

# Install any additional packages you need (example)
# RUN apt-get update && \
#     apt-get install -y git ca-certificates && \
#     apt-get clean && \
#     rm -rf /var/lib/apt/lists/*

# Copy leash-entry from the leash image
COPY --from=leash /usr/local/bin/leash-entry /bin/leash-entry

# Set leash-entry as the entrypoint
ENTRYPOINT ["/bin/leash-entry"]

# Preserve the default CMD from your base image
CMD ["node", "--version"]
```

`leash-entry` wraps your original entrypoint and connects the target container to the Leash manager.

**Important notes:**
- The `leash-entry` binary is located at `/usr/local/bin/leash-entry` in the leash image
- You must preserve the `CMD` directive from your base image, otherwise the entrypoint won't execute commands correctly
- Use the ECR registry URLs (`public.ecr.aws/s5i7k8t3/strongdm/`) rather than GitHub Container Registry

## 2. Build your image

```sh
docker build -t your-target-image .
```

Use whatever tag matches your release process. You can build the Leash manager image later if you need a custom variant.

## 3. Launch with Leash

```sh
leash --image your-target-image
```

Point the CLI at your new image via flags, `LEASH_TARGET_IMAGE`, `TARGET_IMAGE`, or `config.toml` as described in the README and [CONFIG.md](CONFIG.md).
