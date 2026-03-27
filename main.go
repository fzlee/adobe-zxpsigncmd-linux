package main

import (
	"fmt"
	"os"

	"github.com/fzlee/adobe-zxpsigncmd-linux/cmd"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "-selfSignedCert":
		err = cmd.RunSelfSignedCert(os.Args[2:])
	case "-sign":
		err = cmd.RunSign(os.Args[2:])
	case "-verify":
		err = cmd.RunVerify(os.Args[2:])
	case "-help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`adobe-sign - ZXP signing tool (compatible with Adobe ZXPSignCmd)

Usage:
  adobe-sign -selfSignedCert <country> <state> <org> <commonName> <password> <output.p12> [-validityDays N]
  adobe-sign -sign <inputDir> <output.zxp> <cert.p12> <password> [-tsa <url>]
  adobe-sign -verify <input.zxp>
  adobe-sign -help`)
}
