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
FROM ghcr.io/strongdm/coder:latest AS leash

# ... your existing build stages ...

COPY --from=leash /bin/leash-entry /bin/leash-entry
ENTRYPOINT ["/bin/leash-entry"]
```

`leash-entry` wraps your original entrypoint and connects the target container to the Leash manager.

## 2. Build your image

```sh
docker build -t your-target-image .
```

Use whatever tag matches your release process. You can build the Leash manager image later if you need a custom variant.

## 3. Launch with Leash

```sh
leash --image your-target-image --leash-image ghcr.io/strongdm/leash:v0.0.1
```

Point the CLI at your new image via flags, `LEASH_TARGET_IMAGE`, `TARGET_IMAGE`, or `config.toml` as described in the README and [CONFIG.md](CONFIG.md).
