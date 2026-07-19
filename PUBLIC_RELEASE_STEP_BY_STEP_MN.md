# DoubleG Scanner v1.1.0 - GitHub-аар үнэгүй public release хийх

## A. PDF дээр cheat-ийн нэр гаргах

`DoubleGScanner/Data/rules.json` дотор зөвхөн баталгаатай entry нэмнэ:

```json
"knownCheats": [
  {
    "name": "Cheat-ийн бодит нэр",
    "family": "Cheat family / loader family",
    "hashSha256": "64-ТЭМДЭГТТЭЙ-БАТАЛГААТАЙ-SHA256",
    "sourceNote": "Authorized test sample эсвэл баталгаатай эх сурвалж"
  }
]
```

Exact hash таарвал PDF дээр:
- Detected cheat
- Cheat family
- Detection method
- Artifact path
- SHA-256
- Timestamp
- Evidence source
гарна.

`highRiskKeywords` таарсан төдийд cheat-ийн бүтээгдэхүүний нэр зохиож бичихгүй.
Тэр нь зөвхөн manual review / suspicious finding байна.

## B. GitHub public repository үүсгэх

1. github.com дээр account нээнэ.
2. `New repository` дарна.
3. Repository name: `doubleg-scanner`
4. Visibility: `Public`
5. `Create repository` дарна.
6. Энэ source folder-ийн БҮХ файлыг repository-ийн root руу upload/push хийнэ.

Анхаарах зүйл:
- `.github` folder заавал upload хийнэ.
- Source-ийн дотор дахин давхар folder үүсгэж болохгүй.
- Repository root дээр `DoubleGScanner.sln`, `Installer`, `Scripts`, `.github` харагдах ёстой.

## C. Эхний test build

1. Repository -> `Actions`
2. `Build DoubleG Scanner`
3. `Run workflow`
4. Run дууссаны дараа `Artifacts`-аас installer татаж өөрийн Windows test machine/VM дээр шалгана.

Энэ manual run нь public Release үүсгэхгүй.

## D. Public v1.1.0 release автоматаар гаргах

Windows PowerShell / Git Bash ашиглавал:

```powershell
git add .
git commit -m "DoubleG Scanner v1.1.0"
git push
git tag v1.1.0
git push origin v1.1.0
```

Tag GitHub-д очиход workflow:
- Setup EXE build хийнэ
- Portable ZIP build хийнэ
- SHA-256 файлууд гаргана
- Public GitHub Release автоматаар үүсгэнэ
- Бүх файлыг Release assets болгон байрлуулна

## E. Хүмүүст өгөх холбоос

Release page:
`https://github.com/ТАНЫ-НЭР/doubleg-scanner/releases/latest`

Installer шууд татах:
`https://github.com/ТАНЫ-НЭР/doubleg-scanner/releases/latest/download/DoubleGScannerSetup.exe`

Installer filename тогтмол `DoubleGScannerSetup.exe` тул дээрх latest/download холбоос дараагийн хувилбаруудад ч хэвээр ажиллана.

## F. Public болгохын өмнөх заавал хийх тест

- Цэвэр Windows 10 x64
- Цэвэр Windows 11 x64
- Standard user install
- Administrator forensic scan
- Chrome/Edge хаалттай болон нээлттэй үе
- CS2 нээлттэй болон хаалттай үе
- PDF/JSON/hash үүссэн эсэх
- Uninstall бүрэн ажилласан эсэх
- VirusTotal-д public upload хийхээс өмнө sample data байхгүй эсэх

## Чухал

Unsigned setup дээр Windows SmartScreen warning гарч болно.
GitHub-д public байршуулсан нь програмыг code-signed болгохгүй.
Үнэгүй тарааж болно, гэхдээ "ямар ч warning 100% гарахгүй" гэж баталж болохгүй.
