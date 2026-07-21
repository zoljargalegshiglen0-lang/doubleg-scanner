# Signed driver input

Place a Microsoft-signed production `DoubleGKernel.sys` here.

The normal installer includes and installs the kernel driver only when this file
exists and has a valid Authenticode signature. Unsigned CI output is never
silently included in the public installer.
