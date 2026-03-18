# Talos KMS seals

Seal and unseal volumes using Talos KMS functionality.

## Unsealing

Use the `unseal` command to unseal a volume in a Kubernetes
pod. For example, set it up as an init container with LocalPV-ZFS to use an
existing volume as a ZFS volume.

## Getting the bytes to unseal a Talos-encrypted drive

This is useful if you want to, for example, add `--allow-discards` or add a new
key.

To run this directly in Kubernetes for node `<node>`:

```
kubectl run seals --privileged \
  --overrides='{"kind":"Pod", "apiVersion":"v1", "spec": { "nodeSelector": {"kubernetes.io/hostname": "<node>"} }}' \
  --rm -i --tty --image ghcr.io/michaelbeaumont/talos-kms-seals:latest -- \
  --slot 0 --device /dev/sda --endpoint grpcs://your-kms \
  unseal-device
```

The resulting base64 bytes can be used, as is, as the key when running `cryptsetup refresh`,
for example running in a privileged Pod.

### Directly on bytes

If you already have the sealed bytes from the token, use the `unseal-bytes`
subcommand with stdin.

## Sealing

Use the `seal` command to add KMS encryption to an existing volume.
