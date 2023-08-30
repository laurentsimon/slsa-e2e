/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/laurentsimon/slsa-e2e/pkg/policy"
)

var labels []string
var files []string
var sourceURI string
var imageURI string
var builderID string

// evalCmd represents the eval command
var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("eval called")
		fmt.Println("labels:", labels)
		fmt.Println("files:", files)

		if len(files) == 0 {
			fmt.Fprintf(os.Stderr, "no files provided\n")
			os.Exit(1)
		}

		pol, err := policy.FromFiles(files)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create policy: %v\n", err)
			os.Exit(1)
		}

		result := pol.Evaluate(sourceURI, imageURI, builderID)
		if result.Fail() {
			fmt.Fprintf(os.Stderr, "failed to verify: %v\n", result)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "%v\n", result)
	},
}

func init() {
	rootCmd.AddCommand(evalCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// evalCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

	evalCmd.Flags().StringSliceVarP(&labels, "labels", "l", []string{}, "A list of labels")
	evalCmd.Flags().StringSliceVarP(&files, "files", "f", []string{}, "A list of orddered files")
	evalCmd.Flags().StringVarP(&sourceURI, "source-uri", "s", "", "The source-uri")
	evalCmd.Flags().StringVarP(&imageURI, "image-uri", "i", "", "The image-uri")
	evalCmd.Flags().StringVarP(&builderID, "builder-id", "b", "", "The builder ID")

	evalCmd.MarkFlagRequired("files")
	evalCmd.MarkFlagRequired("source-uri")
	evalCmd.MarkFlagRequired("image-uri")
	evalCmd.MarkFlagRequired("builder-id")
}
