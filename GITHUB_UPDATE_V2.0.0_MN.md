# DoubleG Scanner v2.0.0 — Real Kernel Driver

## Яг юу нэмэгдсэн бэ?

`DoubleGKernel.sys` гэсэн жинхэнэ KMDF kernel-mode driver нэмэгдсэн.

Forensic Scan үед:

- Driver kernel дотроос loaded module жагсаалт авна.
- Module path болон image size-ийг scanner руу өгнө.
- Scanner user-mode дээр signature, publisher, SHA-256 шалгана.
- Browser, deleted file, USN болон driver event-тэй тулгана.

Driver kernel address, arbitrary memory болон physical memory-г user-mode руу
өгөхгүй.

## GitHub source update

1. `DoubleGScanner_v2.0.0_GitHub_ReplaceFiles.zip`-ийг задлана.
2. GitHub Desktop → repository → Show in Explorer.
3. Patch-ийн бүх file/folder-ийг repository root руу copy/paste хийнэ.
4. `Replace the files in the destination` сонгоно.
5. Commit:
   `Add real kernel driver scanner v2.0.0`
6. `Commit to main` → `Push origin`.

## Driver build

GitHub → Actions → `Build DoubleG Kernel Driver` → `Run workflow`.

Гарах artifact:

`DoubleGKernel-unsigned-development`

Энэ нь unsigned development build. Normal Windows дээр шууд load болохгүй.

## Production signing

Public хэрэглээнд:

1. Microsoft Hardware Developer Program-аар driver signing хийлгэнэ.
2. Microsoft-signed `DoubleGKernel.sys` авна.
3. Repository дээр:

   `Scripts\Import-SignedKernelDriver.ps1 -DriverPath "C:\path\DoubleGKernel.sys"`

4. Дараа нь app installer workflow ажиллуулна.
5. Signed driver байвал installer автоматаар package дотор оруулж,
   `DoubleGKernel` demand-start kernel service үүсгэнэ.

## Scan result

Signed driver installed/started:

`Kernel & driver integrity — COMPLETED`

Driver байхгүй эсвэл Windows trust хийхгүй бол:

`Kernel & driver integrity — UNAVAILABLE`
`Final verdict — INCOMPLETE`

Ингэснээр scanner kernel scan хийгээгүй мөртлөө худал `NOT DETECTED` гэж
гаргахгүй.

## Аюулгүй байдлын хязгаар

- Arbitrary kernel memory read/write байхгүй
- Physical memory access байхгүй
- Process memory access байхгүй
- Hook, patch, bypass байхгүй
- Kernel address user-mode руу өгөхгүй
- Admin-only control device
