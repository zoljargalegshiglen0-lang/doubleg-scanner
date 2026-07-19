# GitHub Actions-аар үнэгүй Setup EXE build хийх

1. Энэ source folder-ийг шинэ GitHub repository руу upload/push хийнэ.
2. Repository-ийн `Actions` tab нээнэ.
3. `Build DoubleG Scanner` workflow сонгоно.
4. `Run workflow` дарна.
5. Дууссаны дараа run-ийн доод талын `Artifacts` хэсгээс:
   - `DoubleGScanner-installer`
   - `DoubleGScanner-portable-win-x64`
   татна.

Workflow нь Windows runner дээр .NET 10 build хийж, Inno Setup-аар installer үүсгэнэ. Code-signing certificate байхгүй бол installer unsigned хэвээр байна.
