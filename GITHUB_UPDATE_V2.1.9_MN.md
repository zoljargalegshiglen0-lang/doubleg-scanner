# DoubleG Scanner v2.1.9 — Forensic Completion & Timer

## UI

Scan эхлэхэд улаан тасархай wheel тасралтгүй эргэнэ.

Доор нь:

`00:04:27`
`ELAPSED`

гэж секунд явна.

Scan дуусахад `ELAPSED` нь `TOTAL` болно.

## Forensic Scan

Forensic дээр өмнөх хугацаа/record limit-үүдийг авсан:

- MFT 35 секунд / 350,000 record cap байхгүй
- USN 35 секунд / 300,000 record cap байхгүй
- Одоогоор хадгалагдаж байгаа USN journal-ийг эхнээс нь уншина
- All-disk scan 5 минутын global cap-гүй
- Metadata болон deep candidate global cap-гүй
- Defender target хугацааг уртасгасан

Иймээс Forensic удаан байж болно. Wheel болон секунд нь scanner ажиллаж
байгааг харуулна. Cancel ажиллана.

## Unallocated space

Энэ module нь free space-ийг бүхэлд нь byte бүрээр сэргээхгүй, төлөвлөсөн
read-only sample set ажиллуулна. Төлөвлөсөн sample бүрэн дууссан бол
`Completed` гарна. Read error гарвал `Partial` хэвээр.

## Худлаар Completed болгохгүй зүйл

- `Kernel & driver integrity — Unavailable`
  - signed `DoubleGKernel.sys` суулгаагүй бол хэвээр
- `CS2 loaded modules — Partial`
  - CS2 ажиллахгүй бол live module inspection хийх боломжгүй

## GitHub update

1. `DoubleGScanner_v2.1.9_GitHub_ReplaceFiles.zip`-ийг задлана.
2. Repository root руу бүх файлыг copy/paste хийнэ.
3. `Replace the files in the destination` сонгоно.
4. Commit:

`Add forensic completion timer v2.1.9`

5. `Commit to main` → `Push origin`.
6. GitHub Actions → `Build DoubleG Scanner` → шинэ run.
