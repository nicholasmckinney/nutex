/*
Copyright © 2022 Nicholas McKinney
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	inputFilePath  string
	outputFilePath string
)

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extracts the embedded PE/script wrapped by shellcode",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[*] Input File: %s\n", inputFilePath)
		inputBytes, err := os.ReadFile(inputFilePath)
		if err != nil {
			fmt.Printf("[!] unable to read input file. %v", err)
			os.Exit(1)
		}
		unpacker, err := FindUnpacker(inputBytes)
		if err != nil {
			fmt.Printf("[!] unable to find unpacker for file. %v", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Shellcode-Compiler Identified: %s\n", unpacker.Name())
		err = unpacker.UnpackToFile(outputFilePath)
		if err != nil {
			fmt.Printf("[!] unable to unpack payload to file. %v", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Extraction Successful! Output written to: %s\n", outputFilePath)
	},
}

func init() {
	extractCmd.Flags().StringVar(&inputFilePath, "input", "", "Input File Path")
	extractCmd.Flags().StringVar(&outputFilePath, "output", "", "Output File Path")
	rootCmd.AddCommand(extractCmd)
}
