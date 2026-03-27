package zxp

import (
	"archive/zip"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fzlee/adobe-zxpsigncmd-linux/pkg/signer"
)

const mimetypeContent = "application/vnd.adobe.air-ucf-package+zip"

// Package creates a signed ZXP file from the given input directory.
func Package(inputDir, outputPath string, key *rsa.PrivateKey, cert *x509.Certificate) error {
	// Compute file digests from the source directory
	digests, err := signer.ComputeFileDigests(inputDir)
	if err != nil {
		return fmt.Errorf("computing file digests: %w", err)
	}

	// Prepend mimetype digest (mimetype is generated, not from inputDir)
	mimeDigest := sha256Base64([]byte(mimetypeContent))
	allDigests := make([]signer.FileDigest, 0, len(digests)+1)
	allDigests = append(allDigests, signer.FileDigest{Name: "mimetype", Digest: mimeDigest})
	allDigests = append(allDigests, digests...)

	// Build signatures.xml
	sigXML, err := signer.BuildSignaturesXML(allDigests, key, cert)
	if err != nil {
		return fmt.Errorf("building signatures: %w", err)
	}

	// Create the ZXP (ZIP) file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	w := zip.NewWriter(outFile)

	// 1. Write mimetype first (uncompressed, per UCF spec)
	mimeHeader := &zip.FileHeader{
		Name:   "mimetype",
		Method: zip.Store,
	}
	mimeWriter, err := w.CreateHeader(mimeHeader)
	if err != nil {
		return fmt.Errorf("writing mimetype: %w", err)
	}
	if _, err := mimeWriter.Write([]byte(mimetypeContent)); err != nil {
		return err
	}

	// 2. Write META-INF/signatures.xml
	if err := writeZipEntry(w, "META-INF/signatures.xml", []byte(sigXML)); err != nil {
		return err
	}

	// 3. Write all extension files
	for _, d := range digests {
		srcPath := filepath.Join(inputDir, filepath.FromSlash(d.Name))
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", d.Name, err)
		}
		if err := writeZipEntry(w, d.Name, data); err != nil {
			return fmt.Errorf("writing %s to zip: %w", d.Name, err)
		}
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing zip: %w", err)
	}

	return nil
}

// Verify checks if a ZXP file has a valid signature structure.
func Verify(zxpPath string) (*VerifyResult, error) {
	r, err := zip.OpenReader(zxpPath)
	if err != nil {
		return nil, fmt.Errorf("opening ZXP: %w", err)
	}
	defer r.Close()

	result := &VerifyResult{}

	for _, f := range r.File {
		switch f.Name {
		case "mimetype":
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			data, _ := io.ReadAll(rc)
			rc.Close()
			result.Mimetype = string(data)
		case "META-INF/signatures.xml":
			result.HasSignaturesXML = true
		}
	}

	result.IsSigned = result.HasSignaturesXML && result.Mimetype == mimetypeContent

	return result, nil
}

type VerifyResult struct {
	Mimetype         string
	HasSignaturesXML bool
	IsSigned         bool
}

func (r *VerifyResult) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Mimetype:        %s\n", r.Mimetype))
	b.WriteString(fmt.Sprintf("signatures.xml:  %v\n", r.HasSignaturesXML))
	b.WriteString(fmt.Sprintf("Signed:          %v\n", r.IsSigned))
	return b.String()
}

func writeZipEntry(w *zip.Writer, name string, data []byte) error {
	f, err := w.Create(name)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

func sha256Base64(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}
