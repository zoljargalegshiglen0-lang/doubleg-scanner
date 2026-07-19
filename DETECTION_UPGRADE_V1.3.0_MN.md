# v1.3.0 detection test заавар

## Яагаад өмнө нь олдоогүй вэ?

Өмнөх build exact hash/domain database хоосон үед generic нэртэй, ажиллуулаагүй archive/executable-ийг high-confidence finding болгодоггүй байсан. Иймээс file компьютер дээр байсан ч `NOT DETECTED` гарч болох байв.

## v1.3.0 дээр тест хийх

1. Хуучин DoubleG Scanner-ийг хаана.
2. v1.3.0 setup-ийг install/upgrade хийнэ.
3. UAC гарвал зөвшөөрнө. Defender module administrator session-д ажиллана.
4. Full scan сонгогдсон эсэхийг шалгана.
5. Consent checkbox → Start scan.
6. Microsoft Defender module дуусахыг хүлээнэ.
7. Result:
   - Defender эсвэл exact hash танивал `DETECTED`.
   - Recent unsigned executable/archive эсвэл static correlation байвал `REVIEW`.
   - Module ажиллаагүй бол Coverage дээр `Unavailable/Partial` харагдана.
8. PDF-ийн Findings болон Scan Coverage хэсгийг шалгана.

## Бодит cheat sample-ийг ажиллуулахгүй

Downloaded sample-ийг нээх, extract хийх, password оруулах, allowlist/exclusion нэмэх хэрэггүй. Scanner болон Defender-д зөвхөн read-only scan хийлгэнэ. Тест дууссаны дараа Windows Security-ийн зөвлөмжийг дагана.

## Exact нэртэй detection

Microsoft Defender танивал threat name PDF дээр автоматаар гарна. Defender танихгүй ч exact SHA-256 баталгаатай бол `Data/rules.json` → `knownCheats` дотор нэртэй entry нэмнэ.
