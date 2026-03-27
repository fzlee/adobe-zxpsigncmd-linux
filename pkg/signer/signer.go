package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const xmldsigNS = "http://www.w3.org/2000/09/xmldsig#"

// FileDigest holds a file path and its SHA-256 digest.
type FileDigest struct {
	Name   string
	Digest string // base64-encoded SHA-256
}

// ComputeFileDigests walks inputDir and computes SHA-256 digests for all files.
func ComputeFileDigests(inputDir string) ([]FileDigest, error) {
	var digests []FileDigest

	err := filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		digests = append(digests, FileDigest{
			Name:   relPath,
			Digest: base64.StdEncoding.EncodeToString(h.Sum(nil)),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(digests, func(i, j int) bool {
		return digests[i].Name < digests[j].Name
	})

	return digests, nil
}

var selfClosingTagRe = regexp.MustCompile(`<(\w+)(\s[^>]*)/>`)

// c14n applies basic XML Canonical XML 1.0 transformations:
// 1. Inject inherited xmlns declaration
// 2. Expand all self-closing tags to <tag ...></tag>
func c14n(xml string, inheritedNS string) string {
	result := xml
	if inheritedNS != "" {
		// Insert xmlns into the opening tag of the root element.
		// <Tag attr="..."> -> <Tag xmlns="..." attr="...">
		// <Tag>            -> <Tag xmlns="...">
		closeBracket := strings.Index(result, ">")
		firstSpace := strings.Index(result, " ")
		nsAttr := ` xmlns="` + inheritedNS + `"`
		if firstSpace > 0 && firstSpace < closeBracket {
			// Has attributes: insert before first attribute
			result = result[:firstSpace] + nsAttr + result[firstSpace:]
		} else {
			// No attributes: insert before closing >
			result = result[:closeBracket] + nsAttr + result[closeBracket:]
		}
	}
	// Expand self-closing tags
	result = selfClosingTagRe.ReplaceAllString(result, `<$1$2></$1>`)
	return result
}

// BuildSignaturesXML creates the complete XMLDSig signatures.xml content.
func BuildSignaturesXML(digests []FileDigest, key *rsa.PrivateKey, cert *x509.Certificate) (string, error) {
	// 1. Build <Manifest> element (output form with self-closing tags)
	manifestXML := buildManifest(digests)

	// 2. Canonicalize and compute SHA-256 digest of the Manifest
	canonicalManifest := c14n(manifestXML, xmldsigNS)
	manifestDigest := sha256Base64([]byte(canonicalManifest))

	// 3. Build <SignedInfo> element (output form)
	signedInfoXML := buildSignedInfo(manifestDigest)

	// 4. Canonicalize <SignedInfo> and sign with RSA-SHA1
	canonicalSignedInfo := c14n(signedInfoXML, xmldsigNS)
	h := crypto.SHA1.New()
	h.Write([]byte(canonicalSignedInfo))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("RSA signing: %w", err)
	}

	signatureValue := base64Wrap(base64.StdEncoding.EncodeToString(sig))
	certB64 := base64Wrap(base64.StdEncoding.EncodeToString(cert.Raw))

	// 5. Assemble the final signatures.xml
	xml := fmt.Sprintf(`<signatures>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="PackageSignature">
%s
<SignatureValue Id="PackageSignatureValue">%s</SignatureValue>

<KeyInfo>
<X509Data>
<X509Certificate>%s
</X509Certificate>
</X509Data>
</KeyInfo>
<Object>
%s
</Object>
</Signature>
</signatures>`, signedInfoXML, signatureValue, certB64, manifestXML)

	return xml, nil
}

func buildManifest(digests []FileDigest) string {
	var refs strings.Builder
	for _, d := range digests {
		refs.WriteString(fmt.Sprintf(
			`<Reference URI="%s"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>%s</DigestValue></Reference>`,
			d.Name, d.Digest,
		))
	}
	return fmt.Sprintf("<Manifest Id=\"PackageContents\">\n%s</Manifest>", refs.String())
}

func buildSignedInfo(manifestDigest string) string {
	return fmt.Sprintf(`<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference Type="http://www.w3.org/2000/09/xmldsig#Manifest" URI="#PackageContents">
<Transforms>
<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<DigestValue>%s</DigestValue>
</Reference>
</SignedInfo>`, manifestDigest)
}

func sha256Base64(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func base64Wrap(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}
