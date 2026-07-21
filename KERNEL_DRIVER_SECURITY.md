# DoubleGKernel Security Boundary

`DoubleGKernel.sys` is a narrowly scoped read-only KMDF driver.

## Allowed kernel operation

The driver calls `AuxKlibQueryModuleInformation` to obtain the loaded operating-
system image list. It returns only each module's path and image size.

## Data intentionally withheld

Kernel image base addresses are not copied to user mode. The protocol has no
address field.

## Operations intentionally absent

- Arbitrary virtual or physical memory access
- Process memory access
- Kernel object handles
- Driver/process hiding
- SSDT, IDT, callback, dispatch-table, or code patching
- Signature enforcement bypass
- Driver loading of third-party files
- User-supplied pointers or METHOD_NEITHER IOCTLs

## Access control

The named control device is available only to SYSTEM and built-in Administrators.
IOCTLs use `METHOD_BUFFERED`, specify `FILE_READ_DATA`, validate access, validate
all structure sizes, zero output buffers, and cap internal allocations.

## Signing

The repository and CI create an unsigned development `.sys`. It is not silently
inserted into a public installer. A production release requires a trusted signed
driver and should be tested with HVCI/Memory Integrity and Driver Verifier on a
separate test system.
