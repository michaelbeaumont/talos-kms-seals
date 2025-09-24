# Talos KMS seals

Seal and unseal volumes using Talos KMS functionality.

## Unsealing

Use the `unseal` command + docker command to unseal a volume in a Kubernetes
pod. For example, set it up as an init container with LocalPV-ZFS to use an
existing volume as a ZFS volume.

## Sealing

Use the `seal` command to add KMS encryption to an existing volume.
