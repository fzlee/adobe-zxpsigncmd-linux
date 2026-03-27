package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fzlee/adobe-zxpsigncmd-linux/pkg/cert"
	"github.com/fzlee/adobe-zxpsigncmd-linux/pkg/zxp"
)

// RunSign handles the -sign command.
// Args: <inputDir> <output.zxp> <cert.p12> <password> [-tsa <url>]
func RunSign(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: adobe-sign -sign <inputDir> <output.zxp> <cert.p12> <password> [-tsa <url>]")
	}

	inputDir := args[0]
	outputPath := args[1]
	certPath := args[2]
	password := args[3]

	// Validate input directory exists
	info, err := os.Stat(inputDir)
	if err != nil {
		return fmt.Errorf("input directory %s: %w", inputDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", inputDir)
	}

	// Ensure output directory exists
	outDir := filepath.Dir(outputPath)
	if outDir != "" && outDir != "." {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Load certificate
	key, certificate, err := cert.LoadP12(certPath, password)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}

	// Create signed ZXP
	if err := zxp.Package(inputDir, outputPath, key, certificate); err != nil {
		return fmt.Errorf("packaging ZXP: %w", err)
	}

	fmt.Printf("Signed ZXP created: %s\n", outputPath)
	return nil
}
