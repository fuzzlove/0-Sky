# 0-Sky 1.0.0 pre-release 6

This pre-release corrects Crane 1.3.9 container selection on the measured
iOS 27 SRD build without changing the AppSync Unified or AFC2 adaptations.

## Crane container menu

- Replaces Crane's literal
  `com.opa334.crane.to-replace-with-container-selection` menu entry at the
  iOS 27 `UIMenu` children boundary.
- Uses Crane's own exported `crane_replacementMenu` implementation so container
  discovery, names, and actions remain owned by Crane.
- Requires the exact reviewed, signed `CraneSB.dylib` SHA-256 before resolving
  or calling that implementation.
- Installs only after Crane's hooks have settled and retains bounded diagnostics
  for the compatibility decision and replacement count.
- Updates the converter and device bridge to enforce the exact source, binary,
  filter, and transformation hashes for this variant.

## Verification

Verified on an authorized Apple Security Research Device with:

- Hardware model: `iPhone13,2` (iPhone 12)
- OS: iOS 27.0, build `24A5390f`
- Crane package: 1.3.9 with the local `+0sky19` adaptation
- Compatibility adapter: `ios27-springboard-menu-children-v6`

The device diagnostic recorded the reviewed Crane image and replacement symbol
as verified, observed one sentinel, performed one replacement through
`CraneSB.crane_replacementMenu`, and reached state 4. The operator then visually
confirmed that named containers replaced the placeholder. No Crane quarantine
or new SpringBoard crash was present after the settled test.

The host suite passes all 118 tests with the repository virtual environment.
The paid Crane package and device-derived artifacts are not included in this
public source release.

