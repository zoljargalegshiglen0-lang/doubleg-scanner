# DoubleG Scanner v2.2.0 — Advanced Runtime, Persistence & DMA Review

## Нэмэгдсэн 5 шинэ module

### 1. CS2 process-handle access
Одоо ажиллаж буй process-уудаас `cs2.exe` рүү live handle барьж байгаа эсэхийг шалгана.

Retain хийх access:
- `PROCESS_VM_READ`
- `PROCESS_VM_WRITE`
- `PROCESS_VM_OPERATION`
- `PROCESS_CREATE_THREAD`
- `PROCESS_DUP_HANDLE`
- `PROCESS_SUSPEND_RESUME`
- `PROCESS_SET_INFORMATION`

Scanner нь CS2 memory-г унших, бичихгүй. Зөвхөн Windows handle table metadata болон access mask-ийг шалгана.

### 2. CS2 overlay windows
CS2 window-тай их хэмжээгээр давхцсан top-level window дээр:
- layered
- topmost
- click-through
- no-activate
- overlap ratio
- owner process path/signature/hash

шалгана. Steam, Discord, NVIDIA, capture/accessibility software зэрэг legitimate overlay байж болох тул overlay дангаараа confirmed detection болохгүй.

### 3. Services and scheduled tasks
Дараах persistence metadata-г шалгана:
- non-driver Windows services
- automatic start
- service command / ServiceDll
- Task Scheduler executable actions
- task command, arguments, working directory
- enabled state
- user-writable target
- signature / SHA-256 for suspicious targets

### 4. CS2 executable-memory map
Forensic mode дээр `VirtualQueryEx` ашиглан CS2-ийн committed executable memory map-ийг шалгана.

Retain хийх зүйл:
- executable `MEM_PRIVATE`
- normal image module-д хамаарахгүй executable `MEM_MAPPED`
- тухайн region дотор эхэлсэн thread start address-ийн тоо

Scanner memory bytes/content-ийг уншихгүй. Thread start + private executable region correlation нь manual-map/injection төрлийн хамгийн хүчтэй runtime indicator болно.

### 5. PCIe and DMA device review
Forensic mode дээр PCI/USB PnP metadata-аас:
- distinctive DMA tooling/device alias
- PCILeech / LeechCore / USB3380 / FT601/FTD3XX төрлийн trace
- FPGA-related review alias

шалгана.

**Анхаарах:** FPGA/DMA device name, Hardware ID, firmware identity spoof хийж болдог. Төхөөрөмж дангаараа cheat гэдгийг батлахгүй. Hardware alias + DMA software/execution/file/service/task trace давхцсан үед л high-confidence correlation гарна.

## Шинэ correlation rules

- injection-capable CS2 handle + strong overlay, ижил PID
- private executable memory дотор CS2 thread start + external injection-capable handle
- DMA hardware alias + independent DMA software/activity trace
- enabled service/task + unsigned user-writable high-risk target

## Kernel driver

`Kernel & driver integrity` module-ийн existing `DoubleGKernel.sys` integration хэвээр.

Бодит kernel-mode loaded-module enumeration ажиллахын тулд:
1. `Driver/DoubleGKernel` source-ийг WDK-аар build хийх
2. production code-signing certificate-аар sign хийх
3. signed driver-ийг install/package хийх

Unsigned эсвэл missing driver-ийг scanner худлаар `Completed` болгохгүй; `Unavailable` хэвээр гаргана. Энэ patch production signing certificate үүсгэхгүй.

## GitHub update

1. `DoubleGScanner_v2.2.0_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Доторх бүх file/folder-ийг cloned `doubleg-scanner` repository root руу copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. GitHub Desktop commit:

```text
Add advanced runtime and DMA detection v2.2.0
```

5. `Commit to main` → `Push origin`.
6. GitHub → Actions → `Build DoubleG Scanner` → шинэ run ажиллуулна.
7. Хуучин run дээр Re-run хийхгүй.

## Шалгах

### Quick Scan
- `CS2 process-handle access`
- `CS2 overlay windows`

CS2 ажиллаагүй бол эдгээр нь `Partial` гарах нь зөв.

### Full Scan
- Quick-ийн шинэ module-ууд
- `Services and scheduled tasks`

### Forensic Scan
- дээрх бүгд
- `CS2 executable-memory map`
- `PCIe and DMA device review`
- existing signed-kernel-driver integrity module

## Detection-ийн бодит хязгаар

100% cheat detection боломжгүй. Private/new build, firmware-spoofed DMA, hypervisor/SMM, external second-PC overlay, clean reboot, evidence wiping, signed-abused driver болон scanner ажиллахаас өмнө унтарсан fileless cheat зэргийг software-only scanner бүрэн баталгаатай барих боломжгүй.

v2.2.0 нь filename-only scan биш; runtime + memory map + handle + overlay + persistence + driver + disk/browser forensic + DMA correlation ашиглаж false positive-ийг багасгах зорилготой.
