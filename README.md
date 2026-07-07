# SoapUI Attachment Signing Plugin

Signs the MIME/MTOM attachments of a SOAP request with an XML signature, following the
[WS-Security SOAP-with-Attachments (SwA) Profile 1.1](http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1).
The result is a standard `wsse:Security` header containing an X.509 `BinarySecurityToken` and a
`ds:Signature` with one `ds:Reference` per signed attachment (`URI="cid:..."`).

It plugs into the free/open-source **SoapUI** (not ReadyAPI) using SoapUI's public plugin API
(`com.eviware.soapui.plugins`).

## Features

- **Sign Attachments...** context-menu action in the Navigator tree, on both:
  - a plain interface-level Request (**Interfaces > Service > Operation > Request N**), and
  - a SOAP Test Request step inside a TestCase.

  Lets you pick a keystore/alias, a transform, which attachments to sign, and sign immediately.
- **Automatic signing on send**: the same dialog has a checkbox to sign every attachment of every
  request in the project automatically, right before it goes out over HTTP(S).
- Reuses SoapUI's existing **Project > WS-Security Configurations > Keystores** so key material is
  managed exactly like it already is for SoapUI's built-in body-signing feature - no separate
  keystore UI to configure.
- Two transform modes:
  - **Content** (default, recommended): digests only the attachment's payload bytes. Robust and
    interoperable.
  - **Complete**: digests a reconstructed MIME entity (headers + payload). Matches the SwA profile's
    "Complete" transform, but is fragile - see *Limitations* below.

## Building

Requires Java 8+ and Maven, and a dependency on the `soapui` core library that the plugin is
compiled against.

The most reliable approach is to install *your own* SoapUI installation's jar into your local Maven
repository first (this guarantees an exact API match with the SoapUI version you'll actually load
the plugin into):

```bash
# adjust the path and version to your SoapUI installation
mvn install:install-file \
  -Dfile=/path/to/SoapUI-5.9.0/lib/soapui-5.9.0.jar \
  -DgroupId=com.smartbear.soapui -DartifactId=soapui -Dversion=5.9.0 -Dpackaging=jar

mvn -Dsoapui.version=5.9.0 package
```

Alternatively, `pom.xml` also declares SmartBear's own Maven repository
(`https://www.soapui.org/repository/maven2/`), which has historically hosted `com.smartbear.soapui:soapui`
builds; if that coordinate resolves for your version, a plain `mvn package` is enough.

The build produces `target/soapui-attachment-signing-plugin-1.0.0.jar`. It has no bundled runtime
dependencies - everything it uses beyond the JDK (`javax.xml.crypto.dsig`, part of the JDK since
Java 6) is already on SoapUI's own classpath (`soapui.jar`, WSS4J, log4j2).

## Installing into SoapUI

Copy the built jar into SoapUI's plugins directory and restart SoapUI:

- Linux/macOS: `~/.soapuios/plugins/` (or `<SoapUI install dir>/bin/plugins/`)
- Windows: `%USERPROFILE%\.soapuios\plugins\`

SoapUI's Plugin Manager (`File > Preferences > Plugins`, or the "Manage Plugins" toolbar icon) can
also install the jar directly if you prefer a GUI.

## Usage

1. Configure a keystore under **Project > WS-Security Configurations > Keystores** (this is a
   built-in SoapUI feature; the plugin does not add its own keystore UI).
2. In the Navigator tree, right-click a Request that has one or more attachments - either a plain
   Request under **Interfaces > Service > Operation**, or a SOAP Test Request step inside a
   TestCase - and choose **Sign Attachments...**.
3. Pick the keystore, the key alias and its password, the transform, and which attachments to sign,
   then click **Sign Now** - the request's XML is updated immediately with the signature.
4. To have this happen automatically on every send instead, check **"Automatically sign every
   attachment on every send"** and click **Save Settings**. This is a project-wide setting (stored
   as project custom properties named `AttachmentSigning.*`, visible/editable under the project's
   Custom Properties tab). The stored password supports SoapUI property expansion (e.g.
   `${#Project#myKeyPassword}`) if you don't want it stored in the project file in plain text.

## Limitations

- The **Complete** transform reconstructs MIME headers (Content-Type, Content-Transfer-Encoding,
  Content-ID) itself; it does not capture whatever exact bytes SoapUI's HTTP transport ultimately
  puts on the wire. If the receiver's WS-Security stack reconstructs slightly different header
  bytes (ordering, folding, casing), the signature will not validate even though the attachment
  content itself is untouched. This is a known general weakness of the SwA "Complete" transform,
  not specific to this plugin - prefer **Content** unless the receiver specifically requires
  "Complete" semantics.
- Only RSA signing keys are supported (signature method is fixed to `rsa-sha256`); EC/DSA keys are
  not currently handled.
- Automatic signing applies to every attachment present on a request; there is no per-attachment
  include/exclude list for the automatic mode (the manual dialog does let you pick attachments for
  an on-demand "Sign Now").
- Tested against SoapUI's WSS4J 1.6.17 / log4j2 2.26.0 dependency versions; if your SoapUI ships
  materially different versions of these, adjust the properties in `pom.xml` to match.
