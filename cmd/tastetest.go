/*
Copyright © 2022 Nicholas McKinney
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// tastetestCmd represents the tastetest command
var tastetestCmd = &cobra.Command{
	Use:   "tastetest",
	Short: "Identify the type of shellcode-wrapper",
	Long: `Identify the type of shellcode wrapping the embedded PE file or script. Types identified include:
	
* pe2shc (https://github.com/hasherezade/pe_to_shellcode)
* monoxgas sRDI (https://github.com/monoxgas/sRDI)
* donut (https://github.com/TheWover/donut)`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inputFilePath := args[0]
		fmt.Printf("[*] Input file: %s\n", inputFilePath)
		content, err := os.ReadFile(inputFilePath)
		if err != nil {
			fmt.Printf("[!] %v", err)
			os.Exit(1)
		}

		unpacker, err := FindUnpacker(content)

		fmt.Printf("[*] Shellcode-Compiler Identified: %s\n", unpacker.Name())
		information, err := unpacker.Identified()
		if err != nil {
			fmt.Printf("[!] %v", err)
			os.Exit(1)
		}
		fmt.Printf("%s", information)
	},
}

func init() {
	rootCmd.AddCommand(tastetestCmd)
}
