# DoubleG Scanner v2.2.4 - False-positive болон report clarity fix

## Гол засвар

- Microsoft Defender, OneDrive, Visual Studio targeting packs, GitHub Desktop-ийн embedded Git, WindowsApps/Game Bar, WinSxS, Package Cache болон DoubleG Scanner өөрийгөө generic static string-ээр cheat гэж гаргахыг зогсоосон.
- `client.dll`, `OpenProcess`, `ReadProcessMemory`, `CreateToolhelp32Snapshot`, `bhop` зэрэг ганц/ерөнхий string-ийг cheat-ийн нотолгоо гэж үзэхээ больсон.
- Static detection нь aimbot/triggerbot/wallhack/ragebot/skinchanger/kdmapper/iqvw64e.sys зэрэг distinctive indicator + CS2/injection correlation шаардана.
- `@sapphire/*` Node package зэрэг cheat нэртэй давхацсан developer dependency-г suppress хийсэн.
- Google search, ChatGPT conversation зэрэг page title match-ийг cheat detection гэж гаргахгүй.
- Browser visit/download нь `CHEAT WEBSITE TRACE - NOT PROOF OF USE` гэсэн supporting trace болно; confirmed cheat count болон risk-д full score нэмэхгүй.
- DoubleG/Novacs installer, POS/OnisShop installer зэрэг энгийн download-delete activity report-оос хасагдсан.
- Confirmed cheat card нь улаанаар `CHEAT DETECTED` болон `CHEAT: <name>` гэж шууд харуулна.
- Defender result нь `MALWARE / DRIVER THREAT` гэж тусдаа харагдана.
- Risk score зөвхөн confirmed detection-д full weight өгч, review-only evidence-г бага capped weight-аар тооцно.
- Confirmed cheat/threat илэрсэн бол нэг forensic module unavailable байсан ч үндсэн verdict `THREATS DETECTED` гарна; coverage limitation Trust Map дээр тусдаа үлдэнэ.

## Confirmed хэвээр үлдэх detection

- Exact SHA-256 cheat/driver match
- CS2-д loaded named cheat module
- Running named cheat process
- Named cheat executable/archive + distinctive technical indicators
- Named cheat execution trace
- Browser + credible local/execution correlation
- Private executable thread + injection-capable process correlation
- DMA hardware + independent DMA software/activity correlation

## Анхаарах

100% detection батлах боломжгүй. False-positive-г бууруулахын тулд weak heuristic-ийг report-оос хассан тул шинэ/private cheat нь named signature, runtime correlation эсвэл distinctive code indicator байхгүй бол review-д орохгүй байж болно.
