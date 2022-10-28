/*
Copyright © 2022 Nicholas McKinney
*/
package cmd

import (
	"fmt"
	"nutextractor/internal/common"
	"nutextractor/internal/donut"
	"nutextractor/internal/monoxgas"
	"nutextractor/internal/pe2shc"
	"os"

	"github.com/spf13/cobra"
)

var unpackerFactories = [...]common.UnpackerFactory{
	&monoxgas.Factory{},
	&pe2shc.Factory{},
	&donut.Factory{},
}

func FindUnpacker(content []byte) (common.Unpacker, error) {
	var unpackers []common.Unpacker
	for _, factory := range unpackerFactories {
		unpacker := factory.Build(content)
		unpackers = append(unpackers, unpacker)
	}

	var unpacker common.Unpacker
	for _, identifier := range unpackers {
		if identifier.CanUnpack() {
			unpacker = identifier
			break
		}
	}

	if unpacker == nil {
		return nil, fmt.Errorf("no compatible unpacker found")
	}
	return unpacker, nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nutextractor",
	Short: "Identifies and extracts PE files and scripts that are wrapped by a shellcode loader",
	Long: `Identifies and extracts "shellcode-compiled" PE files and scripts, including those wrapped by:

* pe2shc (https://github.com/hasherezade/pe_to_shellcode)
* monoxgas sRDI (https://github.com/monoxgas/sRDI)
* donut (https://github.com/TheWover/donut)`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}
