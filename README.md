# adobe-zxpsigncmd-linux

An unofficial, open-source reimplementation of Adobe's `ZXPSignCmd` tool, written in pure Go with zero CGO dependencies. It can create self-signed certificates, sign Adobe CEP extensions into `.zxp` packages, and verify existing `.zxp` signatures.

## Disclaimer

**This is NOT an official Adobe product.** This tool is an independent reimplementation created for convenience (especially on platforms where the official `ZXPSignCmd` binary is unavailable, such as Linux ARM64). Use it at your own risk. The author(s) assume no responsibility or liability for any issues, damages, or losses arising from the use of this software.

## Features

- **Self-signed certificate generation** -- Create PKCS#12 (`.p12`) certificates for extension signing
- **ZXP signing** -- Package and sign CEP extensions using XMLDSig, fully compatible with Adobe's verification
- **ZXP verification** -- Check signature structure of `.zxp` files
- **Pure Go** -- No CGO, no OpenSSL dependency, cross-compiles to any platform
- **Verified compatible** -- Output passes `ZXPSignCmd -verify` from Adobe's official tool (v4.1.3)

## Installation

### Go install

```bash
go install github.com/fzlee/adobe-zxpsigncmd-linux@latest
```

### Build from source

```bash
git clone https://github.com/fzlee/adobe-zxpsigncmd-linux.git
cd adobe-zxpsigncmd-linux
go build -o adobe-sign .
```

### Docker

```bash
docker pull fzlee/zxpsigncmd-linux
```

## Usage

The CLI mirrors Adobe's `ZXPSignCmd` interface:

### Create a self-signed certificate

```bash
adobe-sign -selfSignedCert <country> <state> <org> <commonName> <password> <output.p12> [-validityDays N]
```

Example:

```bash
adobe-sign -selfSignedCert CN Beijing MyCompany "My Plugin" mypassword cert.p12 -validityDays 3650
```

### Sign a CEP extension

```bash
adobe-sign -sign <inputDir> <output.zxp> <cert.p12> <password>
```

Example:

```bash
adobe-sign -sign ./my-extension output.zxp cert.p12 mypassword
```

### Verify a ZXP package

```bash
adobe-sign -verify <input.zxp>
```

### Docker usage

Mount your local directories into the container to sign extensions:

**Create a certificate:**

```bash
docker run --rm -v $(pwd)/certs:/certs fzlee/zxpsigncmd-linux \
  -selfSignedCert CN Beijing MyCompany "My Plugin" mypassword /certs/cert.p12 -validityDays 3650
```

**Sign an extension:**

```bash
docker run --rm \
  -v $(pwd)/my-extension:/ext \
  -v $(pwd)/certs:/certs \
  -v $(pwd)/output:/output \
  fzlee/zxpsigncmd-linux \
  -sign /ext /output/plugin.zxp /certs/cert.p12 mypassword
```

**Verify a ZXP:**

```bash
docker run --rm -v $(pwd)/output:/output fzlee/zxpsigncmd-linux \
  -verify /output/plugin.zxp
```

## How it works

The tool implements the XMLDSig signing format that Adobe CEP expects:

1. Computes SHA-256 digests of all files in the extension directory
2. Builds an XMLDSig `<Manifest>` containing all file references and digests
3. Computes the SHA-256 digest of the C14N-canonicalized Manifest
4. Signs the C14N-canonicalized `<SignedInfo>` with RSA-SHA1
5. Packages everything into a ZIP archive with `mimetype` and `META-INF/signatures.xml`

## License

MIT
