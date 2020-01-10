# About this library
This library implements an Elliptic Curve Digital Signature Algorithm ([ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)) based on Curve 25519, in short [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519). This implementation was inspired by the Ed25519 implementation from Hans Wolff (cf. https://github.com/hanswolff/ed25519) and the Chaos.NaCl library (cf. https://github.com/CodesInChaos/Chaos.NaCl).

# .NET Core 3.1 LTS+ only
This library was implemented especially for .NET Core 3.1 and newer. It is therefore not available for .NET Standard 2.x or the outdated .NET Framework. This design decision was made based on the following background: (a) The .NET Framework will not be further developed (cf. https://devblogs.microsoft.com/dotnet/net-core-is-the-future-of-net/); (b) as of .NET 5.0, the .NET Standard is no longer expected to be required because Mono and the .NET Core will be merged together into the new .NET 5 (cf. https://devblogs.microsoft.com/dotnet/introducing-net-5/).

# Test cases
The library contains basic test cases to ensure the core functions of signing and validation. In addition to the basic tests, the tests contained in RFC8032 are also performed, cf. https://tools.ietf.org/html/rfc8032#section-7.1

# Performance
This implementation was not optimized for best possible performance. Instead, the focus was on the readability of the code and its correctness. If you are looking for an Ed25519 library for automated signing of as many messages as possible, this library is probably not suitable. The Chaos.NaCl library (cf. https://github.com/CodesInChaos/Chaos.NaCl) is might suitable for such cases.

# Citation
The library can also be cited in scientific works, for example as follows:

*Sommer, Thorsten (2020): Ed25519. Github: https://github.com/SommerEngineering/Ed25519, DOI: [doi.org/10.5281/zenodo.3604373](https://doi.org/10.5281/zenodo.3604373)*

# License
This library uses the BSD 3-clause license.