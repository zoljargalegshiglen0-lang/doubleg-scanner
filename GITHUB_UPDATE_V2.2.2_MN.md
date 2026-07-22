# DoubleG Scanner v2.2.2 - Original Report Design

Энэ patch нь өмнөх report layout-ыг бүрэн сольж, Novacs-тэй төстэй харагдах хэсгүүдийг арилгана.

## Шинэ бүтэц

1. **Integrity Case Report** - том кейсийн гарчиг, rectangular assessment card, system identity strip.
2. **Evidence Profile** - direct, correlated, review, completed module гэсэн тусдаа картууд.
3. **Evidence Ledger** - finding бүр дугаартай, confidence segment, source, score-той.
4. **Coverage & Trust Map** - scan module бүр тусдаа tile.
5. **DMA Correlation Gate** - device + software + correlation гэсэн 3 шат.
6. **Evidence Appendix** - бүх evidence record болон integrity мэдээлэл.
7. Footer бүрт **by xanny** орно.

## GitHub дээр хийх

- ZIP-ийн доторх файлуудыг repository root дээр copy хийнэ.
- Replace the files in the destination сонгоно.
- Commit: `Replace PDF report with original case-file design v2.2.2`
- GitHub Actions build-ийг ажиллуулна.
