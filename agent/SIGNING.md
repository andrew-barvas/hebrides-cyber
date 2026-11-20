# Signing, notarisation and packaging (owner steps)

The `Device Agent` workflow (`.github/workflows/agent.yml`) builds **unsigned**
binaries. Customers shouldn't run unsigned binaries: Windows SmartScreen warns
on them, macOS Gatekeeper blocks them, and nobody can tell a genuine binary
from a tampered one. Signing needs credentials only the owner can obtain, so
this file is the pipeline to add once they exist. The owner items (code-signing
certificate, Apple Developer Program, packaging decision) are tracked as OT
items in the private docs repo.

## What the owner needs to get

| For | What | Notes |
|---|---|---|
| Windows | An OV or EV **code-signing certificate** from a CA (DigiCert, Sectigo, GlobalSign…), or **Azure Trusted Signing** | Since June 2023 the private key must live on a hardware token or a cloud HSM. Azure Trusted Signing or Azure Key Vault (Premium, HSM-backed) keeps it out of CI runners. EV builds SmartScreen reputation at once; OV builds it over downloads. |
| macOS | **Apple Developer Program** membership (organisation) | Gives a *Developer ID Application* certificate (sign) and *Developer ID Installer* (sign the .pkg), plus an App Store Connect API key for `notarytool`. Organisation enrolment needs a D-U-N-S number. |
| Linux | A **GPG key** for the release (or keyless **cosign** via GitHub OIDC) | Signs `SHA256SUMS`, and the apt/yum repository if one is published. |

## The pipeline to add (a `release` job after `build`)

Trigger on a tag (`agent-v*`), not every push. Pass the version from the tag
to `./build.sh`.

### Windows: Authenticode

```powershell
# Azure Trusted Signing (preferred: no key file anywhere)
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib Azure.CodeSigning.Dlib.dll /dmdf metadata.json hebrides-agent-*-windows-*.exe
# or a Key Vault certificate
AzureSignTool sign -kvu $KV_URL -kvc $CERT_NAME -kvm -tr http://timestamp.digicert.com -td sha256 hebrides-agent-*.exe
signtool verify /pa /v hebrides-agent-*.exe
```

Always timestamp, so signatures stay valid after the certificate expires. Run
on `windows-latest` with OIDC federation to Azure (`azure/login` with
`client-id`/`tenant-id`/`subscription-id`, no stored secret).

### macOS: codesign + notarise

```bash
# Hardened runtime is required for notarisation.
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <Org> (<TEAMID>)" hebrides-agent-darwin-arm64
# A universal binary keeps one download:
lipo -create -output hebrides-agent hebrides-agent-*-darwin-amd64 hebrides-agent-*-darwin-arm64
# A bare binary can't be stapled: notarise inside a .pkg (preferred) or .zip.
pkgbuild --root pkgroot --identifier uk.co.hebridescyber.agent --version "$VERSION" \
  --scripts packaging/macos/scripts --sign "Developer ID Installer: <Org> (<TEAMID>)" hebrides-agent.pkg
xcrun notarytool submit hebrides-agent.pkg --key AuthKey.p8 --key-id "$KEY_ID" --issuer "$ISSUER" --wait
xcrun stapler staple hebrides-agent.pkg
spctl --assess --type install -v hebrides-agent.pkg
```

Runs on `macos-latest`. The certificate (.p12) and API key go in GitHub
secrets, imported into a temporary keychain for the job and deleted after it.

### Linux: checksums and signatures

```bash
gpg --batch --detach-sign --armor dist/SHA256SUMS         # SHA256SUMS.asc
# or, keyless:
cosign sign-blob --yes dist/SHA256SUMS --output-signature SHA256SUMS.sig --output-certificate SHA256SUMS.pem
```

Packages: `nfpm` builds `.deb` and `.rpm` from one YAML, installing the binary
to `/usr/local/bin`, the systemd units from `packaging/linux/`, and an empty
`/etc/hebrides-agent/` (0700).

### Installers (packaging decision first)

Whether the agent ships inside Lookout or as a separate Cyber Essentials
add-on changes the download page, which plan unlocks it
(`src/lib/deviceAgent/access.ts`, one constant) and the installer's branding,
so packaging waits for that decision.

- **Windows:** an MSI (WiX v4) that installs to `Program Files\HebridesCyber`,
  sets the `ProgramData\HebridesCyber` ACL to Administrators + SYSTEM, takes
  the token as an MSI property (`msiexec /i hebrides-agent.msi TOKEN=hcd_…`,
  for Intune/GPO), runs `enrol`, and registers the task from
  `packaging/windows/register-task.ps1`. Sign the MSI as well as the exe.
- **macOS:** the notarised .pkg above, with a `postinstall` that loads the
  launchd plist. MDM deployment passes the token via a configuration profile
  or a post-install script.
- **Linux:** the nfpm packages; `postinst` enables the timer.

### Publishing

Attach the signed artefacts, `SHA256SUMS` and its signature to a GitHub
release, and link the latest from the dashboard's Devices page. Keep the
download host on the same `www` origin or GitHub releases; never a third-party
mirror.

## Checks before the first customer install

- `signtool verify /pa` passes and SmartScreen doesn't warn on a clean VM.
- `spctl --assess` accepts the .pkg on a clean Mac with Gatekeeper on.
- `hebrides-agent inventory` output matches what the OS's own tools show.
- Revoking the device in the dashboard makes the next `report` exit 3.
