package cmd

import (
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/jetstack/vault-unsealer/pkg/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const cfgUnsealPeriod = "unseal-period"
const cfgInit = "init"
const cfgOnce = "once"

type unsealCfg struct {
	unsealPeriod time.Duration
	proceedInit  bool
	runOnce      bool
}

var unsealConfig unsealCfg

// unsealCmd represents the unseal command
var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseals the target Vault instance",
	Long: `This command will verify the Cloud KMS service is accessible, then
	run "vault unseal" against the target Vault instance, using keys from Cloud KMS keyring.

	if  --init flag is specified target vault instance will be initialized befor unsealing.`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgInit, cmd.PersistentFlags().Lookup(cfgInit))
		appConfig.BindPFlag(cfgOnce, cmd.PersistentFlags().Lookup(cfgOnce))

		appConfig.BindPFlag(cfgInitRootToken, cmd.PersistentFlags().Lookup(cfgInitRootToken))
		appConfig.BindPFlag(cfgStoreRootToken, cmd.PersistentFlags().Lookup(cfgStoreRootToken))
		appConfig.BindPFlag(cfgOverwriteExisting, cmd.PersistentFlags().Lookup(cfgOverwriteExisting))

		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		unsealConfig.proceedInit = appConfig.GetBool(cfgInit)
		unsealConfig.runOnce = appConfig.GetBool(cfgOnce)

		store, err := kvStoreForConfig(appConfig)

		if err != nil {
			logrus.Fatalf("error creating kv store: %s", err.Error())
		}

		cl, err := api.NewClient(nil)

		if err != nil {
			logrus.Fatalf("error connecting to vault: %s", err.Error())
		}

		vaultConfig, err := vaultConfigForConfig(appConfig)

		if err != nil {
			logrus.Fatalf("error building vault config: %s", err.Error())
		}

		v, err := vault.New(store, cl, vaultConfig)

		if err != nil {
			logrus.Fatalf("error creating vault helper: %s", err.Error())
		}

		for {
			func() {
				if unsealConfig.proceedInit {
					initialized, err := v.Initialized()
					if err != nil {
						logrus.Errorf("error initializing vault: %s", err.Error())
						exitIfNecessary(1)
						return
					}

					if !initialized {
						logrus.Infof("initializing vault...")
						if err = v.Init(); err != nil {
							logrus.Errorf("error initializing vault: %s", err.Error())
							exitIfNecessary(1)
							return
						} else {
							unsealConfig.proceedInit = false
						}
					} else {
						unsealConfig.proceedInit = false
					}
				}

				sealed, err := v.Sealed()
				if err != nil {
					logrus.Errorf("error checking if vault is sealed: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				// If vault is not sealed, we stop here and wait
				if !sealed {
					exitIfNecessary(0)
					return
				}

				if err = v.Unseal(); err != nil {
					logrus.Errorf("error unsealing vault: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				logrus.Infof("successfully unsealed vault")

				exitIfNecessary(0)
			}()

			// wait before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func exitIfNecessary(code int) {
	if unsealConfig.runOnce {
		os.Exit(code)
	}
}

func init() {
	unsealCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*30, "how often to attempt to unseal the vault instance")
	unsealCmd.PersistentFlags().Bool(cfgInit, false, "initialize vault instantce if not yet initialized")
	unsealCmd.PersistentFlags().Bool(cfgOnce, false, "execute unseal command only once")

	unsealCmd.PersistentFlags().String(cfgInitRootToken, "", "root token for the new vault cluster")
	unsealCmd.PersistentFlags().Bool(cfgStoreRootToken, true, "should the root token be stored in the key store")
	unsealCmd.PersistentFlags().Bool(cfgOverwriteExisting, false, "overwrite existing unseal keys and root tokens, possibly dangerous!")

	RootCmd.AddCommand(unsealCmd)
}
