# Advanced detection notes — v2.2.0

DoubleG Scanner remains local-only and read-only.

## Confidence model

- A single overlay or FPGA device is review-only evidence.
- A live write/injection-capable handle is high-risk unless the owner is trusted and verified.
- A CS2 thread beginning in executable MEM_PRIVATE memory is critical runtime evidence.
- Hardware DMA metadata becomes critical only when independently correlated with DMA software/activity traces.
- Production kernel inspection requires a properly signed `DoubleGKernel.sys`; the application must not claim completed kernel coverage when the driver is missing.

## Operational recommendation

Run Forensic Scan as administrator while CS2 and all normal overlays are active. Keep Steam/Discord/GPU software running so the report can distinguish the normal baseline from untrusted runtime relationships.
