# Browser search detection v2.2.5

## Зөв болсон зүйл
- Google, Bing, DuckDuckGo дээр `CS2 cheat`, `Sysware`, `Neverlose CS2`, `Midnight Free/Lite` зэрэг тодорхой cheat search report-д гарна.
- Card нь улбар шар бөгөөд `SEARCHED: <name> CS2 cheat` гэж ойлгомжтой харагдана.
- Browser search дангаараа confirmed cheat болохгүй, risk score-д confirmed detection хэлбэрээр орохгүй.

## False positive хамгаалалт
- `Midnight movie`, `Osiris mythology`, `Sapphire package` зэрэг ерөнхий утгатай хайлтыг CS2/cheat context байхгүй бол гаргахгүй.
- ChatGPT conversation URL болон YouTube results page-ийг шууд cheat evidence гэж үзэхгүй.
- Known cheat distribution domain руу орсон түүх тусдаа browser website trace хэвээр гарна.
