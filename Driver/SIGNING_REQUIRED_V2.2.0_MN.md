# DoubleGKernel.sys signing requirement

Scanner source already integrates with the read-only `Driver/DoubleGKernel` KMDF project.

`Kernel & driver integrity`-г бодитоор `Completed` болгохын тулд driver binary нь Windows-д зөвшөөрөгдөх production signature-тай байх ёстой. Энэ patch certificate/private key агуулахгүй.

- Test-signing build-ийг public release-д бүү package хий.
- Stolen/leaked certificate ашиглаж болохгүй.
- Driver нь зөвхөн bounded loaded-module metadata гаргах existing read-only design-ээ хадгална.
- Arbitrary process/kernel memory read/write IOCTL бүү нэм.
