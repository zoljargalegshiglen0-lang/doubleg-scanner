# DoubleGKernel.sys

This is the read-only KMDF component used by DoubleG Scanner Forensic Scan.

## Exposed operations

- Query protocol/driver version.
- Enumerate loaded kernel image paths and image sizes.

## Deliberately not implemented

- Arbitrary kernel or physical-memory read/write.
- Process-memory read/write.
- Kernel addresses in user-mode output.
- Hooks, callbacks, object manipulation, hiding, bypasses, or patching.
- Driver/service creation from an unprivileged caller.

The control device grants access only to SYSTEM and the built-in Administrators
group. Every IOCTL requires read access and uses METHOD_BUFFERED with strict
input/output length validation.

The source builds an unsigned development `.sys`. Normal Windows systems require
a properly signed production driver before it can be loaded.
