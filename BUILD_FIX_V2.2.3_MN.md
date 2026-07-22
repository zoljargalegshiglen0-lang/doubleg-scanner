# DoubleG Scanner v2.2.3 build fix

GitHub Actions дээр гарсан дараах compile алдааг зассан:

- `ReportService.cs#L185`: `Image` type not found
- `ReportService.cs#L785`: `Image` type not found

## Засвар

MigraDoc-ийн `Paragraph.AddImage(...)` буцаах төрлийг explicit `Image` гэж зарласныг C# type inference ашиглан `var` болгосон. Ингэснээр `MigraDoc.DocumentObjectModel.Shapes.Image` namespace import шаардлагагүй болно.

```csharp
var image = logo.AddImage(logoPath);
image.LockAspectRatio = true;
```

Version metadata-г `2.2.3` болгосон.
