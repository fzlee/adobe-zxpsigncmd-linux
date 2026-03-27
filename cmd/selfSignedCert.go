package cmd

import (
	"fmt"
	"strconv"

	"github.com/fzlee/adobe-zxpsigncmd-linux/pkg/cert"
)

// RunSelfSignedCert handles the -selfSignedCert command.
// Args: <country> <state> <org> <commonName> <password> <output.p12> [-validityDays N]
func RunSelfSignedCert(args []string) error {
	if len(args) < 6 {
		return fmt.Errorf("usage: adobe-sign -selfSignedCert <country> <state> <org> <commonName> <password> <output.p12> [-validityDays N]")
	}

	config := cert.CertConfig{
		Country:    args[0],
		State:      args[1],
		Org:        args[2],
		CommonName: args[3],
		Password:   args[4],
		ValidDays:  365 * 10, // default 10 years
	}
	outputPath := args[5]

	// Parse optional -validityDays
	for i := 6; i < len(args)-1; i++ {
		if args[i] == "-validityDays" {
			days, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid validityDays: %s", args[i+1])
			}
			config.ValidDays = days
		}
	}

	if err := cert.CreateSelfSignedCert(config, outputPath); err != nil {
		return err
	}

	fmt.Printf("Certificate created: %s\n", outputPath)
	return nil
}
