package cmd

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/jetstack/vault-unsealer/pkg/kv"
	"github.com/jetstack/vault-unsealer/pkg/kv/aws_kms"
	"github.com/jetstack/vault-unsealer/pkg/kv/aws_ssm"
	"github.com/jetstack/vault-unsealer/pkg/kv/local"
	"github.com/jetstack/vault-unsealer/pkg/kv/s3"

	"github.com/jetstack/vault-unsealer/pkg/vault"
)

func vaultConfigForConfig(cfg *viper.Viper) (vault.Config, error) {

	return vault.Config{
		KeyPrefix: "vault",

		SecretShares:    appConfig.GetInt(cfgSecretShares),
		SecretThreshold: appConfig.GetInt(cfgSecretThreshold),

		InitRootToken:  appConfig.GetString(cfgInitRootToken),
		StoreRootToken: appConfig.GetBool(cfgStoreRootToken),

		OverwriteExisting: appConfig.GetBool(cfgOverwriteExisting),
	}, nil
}

func kvStoreForConfig(cfg *viper.Viper) (kv.Service, error) {

	switch cfg.GetString(cfgMode) {
	case cfgModeValueAWSKMS3:
		s3, err := s3.New(
			cfg.GetString(cfgAWSS3Region),
			cfg.GetString(cfgAWSS3Bucket),
			cfg.GetString(cfgAWSS3Prefix),
		)

		if err != nil {
			return nil, fmt.Errorf("error creating AWS S3 kv store: %s", err.Error())
		}

		kms, err := aws_kms.New(s3, cfg.GetString(cfgAWSKMSRegion), cfg.GetString(cfgAWSKMSKeyID))

		if err != nil {
			return nil, fmt.Errorf("error creating AWS KMS kv store: %s", err.Error())
		}

		return kms, nil

	case cfgModeValueAWSKMSSSM:
		ssm, err := aws_ssm.New(cfg.GetString(cfgAWSSSMKeyPrefix))
		if err != nil {
			return nil, fmt.Errorf("error creating AWS SSM kv store: %s", err.Error())
		}

		kms, err := aws_kms.New(ssm, cfg.GetString(cfgAWSKMSRegion), cfg.GetString(cfgAWSKMSKeyID))
		if err != nil {
			return nil, fmt.Errorf("error creating AWS KMS ID kv store: %s", err.Error())
		}

		return kms, nil

	case cfgModeValueLocal:
		return local.New(cfg.GetString(cfgLocalKeyDir))

	default:
		return nil, fmt.Errorf("Unsupported backend mode: '%s'", cfg.GetString(cfgMode))
	}
}
