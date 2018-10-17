package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var appConfig *viper.Viper
var cfgFile string

const cfgSecretShares = "secret-shares"
const cfgSecretThreshold = "secret-threshold"

const cfgMode = "mode"
const cfgModeValueAWSKMSSSM = "aws-kms-ssm"
const cfgModeValueAWSKMS3 = "aws-kms-s3"
const cfgModeValueLocal = "local"

const cfgAWSKMSRegion = "aws-kms-region"
const cfgAWSKMSKeyID = "aws-kms-key-id"
const cfgAWSSSMKeyPrefix = "aws-ssm-key-prefix"

const cfgAWSS3Bucket = "aws-s3-bucket"
const cfgAWSS3Prefix = "aws-s3-prefix"
const cfgAWSS3Region = "aws-s3-region"

const cfgLocalKeyDir = "local-key-dir"

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "vault-unsealer",
	Short: "Automates initialisation and unsealing of Hashicorp Vault.",
	Long: `This is a CLI tool to help automate the setup and management of
Hashicorp Vault.

It will continuously attempt to unseal the target Vault instance, by retrieving
unseal keys from a AWS KMS keyring or local in path
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func configIntVar(key string, defaultValue int, description string) {
	RootCmd.PersistentFlags().Int(key, defaultValue, description)
	appConfig.BindPFlag(key, RootCmd.PersistentFlags().Lookup(key))
}

func configStringVar(key, defaultValue, description string) {
	RootCmd.PersistentFlags().String(key, defaultValue, description)
	appConfig.BindPFlag(key, RootCmd.PersistentFlags().Lookup(key))
}

func init() {
	appConfig = viper.New()
	appConfig.SetEnvPrefix("vault_unsealer")
	replacer := strings.NewReplacer("-", "_")
	appConfig.SetEnvKeyReplacer(replacer)
	appConfig.AutomaticEnv()

	// SelectMode
	configStringVar(
		cfgMode,
		cfgModeValueAWSKMSSSM,
		fmt.Sprintf(`Select the mode to use:
			'%s' => AWS SSM parameter store using AWS KMS encryption;
			'%s' => AWS S3 Object Storage using AWS KMS encryption;
			'%s' => Use local keys in path`,
			cfgModeValueAWSKMSSSM,
			cfgModeValueAWSKMS3,
			cfgModeValueLocal),
	)

	// Secret config
	configIntVar(cfgSecretShares, 1, "Total count of secret shares that exist")
	configIntVar(cfgSecretThreshold, 1, "Minimum required secret shares to unseal")

	// AWS KMS Storage flags
	configStringVar(cfgAWSKMSRegion, "", "The region of the AWS KMS key to encrypt values")
	configStringVar(cfgAWSKMSKeyID, "", "The ID or ARN of the AWS KMS key to encrypt values")

	// AWS SSM Parameter Storage flags
	configStringVar(cfgAWSSSMKeyPrefix, "", "The Key Prefix for SSM Parameter store")

	// AWS S3 Object Storage flags
	configStringVar(cfgAWSS3Bucket, "", "The name of the AWS S3 bucket to store values in")
	configStringVar(cfgAWSS3Prefix, "", "The prefix to use for storing values in AWS S3")
	configStringVar(cfgAWSS3Region, "us-east-1", "The region to use for storing values in AWS S3")

	configStringVar("local-key-dir", "", "Directory of key shares in path")
}
