package cmd

import (
	"fmt"

	"github.com/fzlee/adobe-zxpsigncmd-linux/pkg/zxp"
)

// RunVerify handles the -verify command.
// Args: <input.zxp>
func RunVerify(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: adobe-sign -verify <input.zxp>")
	}

	result, err := zxp.Verify(args[0])
	if err != nil {
		return err
	}

	fmt.Print(result)

	if !result.IsSigned {
		return fmt.Errorf("ZXP is not properly signed")
	}

	fmt.Println("\nSignature structure is valid.")
	return nil
}
