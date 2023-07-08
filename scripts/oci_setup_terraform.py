'''scripts/oci_setup_terraform.py'''

import argparse
import pathlib
import getpass
import textwrap
import sys
import oci
from pyhomelab.logger import logger
from pyhomelab.oci.profiles import (OCIBrowserAuthProfile, OCIAPIProfile)
from pyhomelab.oci import OCIWrapper
import pyhomelab.oci.exceptions


def script_args() -> argparse.ArgumentParser:
    '''User Arguments'''

    parser = argparse.ArgumentParser(description='Setup Terraform Environment')

    group = parser.add_argument_group('General Options')
    group.add_argument('-v', dest='log_level', action='count', default=0,
                       help="Set log level (v - WARNING, vv - INFO, vvv - DEBUG)")
    group.add_argument('-c', '--config-file', dest='config_file', default='~/.oci/config',
                       help='The OCI configuration file to use (Default = ~/.oci/config)')

    group = parser.add_argument_group('OCI Account Options')
    group.add_argument('-p', '--profile', dest='profile', default='DEFAULT',
                       help='Profile to use in config-file (Default = DEFAULT)')
    group.add_argument('--auth', dest='auth_type', default='security_token',
                       choices=['security_token', 'api'],
                       help='Specify how to authenticate, Default = security_token')
    group.add_argument('-r', '--region', dest='region', required=True,
                       help='Primary region for the OCI account')
    group.add_argument('-t', '--tenancy', dest='tenancy', required=None,
                       help='Provide name of tenancy')

    group = parser.add_argument_group('Terraform Service Account Options')
    group.add_argument('--tf-user', dest='tf_user', default='sa-terraform',
                       help='Name of the Terraform Service Account. default = sa-terraform')
    group.add_argument('--tf-user-api-key', dest='tf_user_api_key', default=None,
                       help=('Location of the RSA private key. '
                             'If None, it will create one. Default = None'))
    group.add_argument('--ask-key-passphrase', dest='ask_key_passphrase', action='store_true',
                       help='Prompt for key passphrase')
    group.add_argument('--tf-group', dest='tf_group', default='group-terraform',
                       help=textwrap.dedent('''
Name of the group tf-user should be in to manage policies, default = group-terraform'''))

    group = parser.add_argument_group('Terraform Compartment Options')
    group.add_argument('--tf-compartment', dest='tf_compartment', default='compartment-terraform',
                       help=textwrap.dedent('''
Name of the compartment to store Terraform created resources, default = compartment-terraform'''))

    group = parser.add_argument_group('Terraform Backend Options')
    group.add_argument('--create-tf-backend', dest='create_tf_backend', action='store_true',
                   help=textwrap.dedent('''Create vault to store secrets and compartments
to store automation resources, default = False. This must be True to set the group options.'''))
    group.add_argument('--automation-compartment', dest='automation_compartment',
                       default='compartment-automation',
                       help='Name of the automation compartment. Default = compartment-automation')
    group.add_argument('--vault-name', dest='vault_name', default='vault-automation-secrets',
                       help=textwrap.dedent('''
Name of the Vault to store secrets, default = vault-automation-secrets'''))
    group.add_argument('--vault-key-name', dest='vault_key_name', default='key-secrets',
                       help='Name of the key to encrypt storage and secrets, default=key-secrets')

    return parser


def main() -> None:
    '''Main Function to run'''

    parser = script_args()
    args = parser.parse_args()

    # set logging
    log = logger(name='OCISetupTerraform', log_level=args.log_level)

    # initializing OCI Wrapper
    root_account_profile = OCIBrowserAuthProfile(name=args.profile,
                                                 config_file=args.config_file,
                                                 region=args.region,
                                                 tenancy=args.tenancy,
                                                 log_level=args.log_level)

    try:
        oci_wrapper = OCIWrapper(profile=root_account_profile)
    except oci.exceptions.ProfileNotFound as err:
        log.error(err)
        sys.exit(1)

    # create tf_user
    try:
        tf_user = oci_wrapper.create_user(name=args.tf_user,
                                          description='Terraform Service Account',
                                          freeform_tags={'infra': 'terraform'},
                                          capabilities={'can_use_api_keys': True,
                                                        'can_use_console_password': False})
    except (pyhomelab.oci.exceptions.OCIUserUpdateFailed,
            pyhomelab.oci.exceptions.OCIUserCreationError) as err:
        log.error(err)
        sys.exit(0)

    # api key for tf_user
    if args.tf_user_api_key is None:
        tf_user_api_private_key_file = f"{pathlib.Path.home()}/.oci/{args.tf_user}_rsa.key"
        log.debug("Setting tf_user_api_private_key_file to %s", tf_user_api_private_key_file)
    else:
        tf_user_api_private_key_file = pathlib.Path(args.tf_user_api_key).expanduser()

    if args.ask_key_passphrase is True:
        key_passphrase = getpass.getpass(
                            prompt=f"Enter passphrase for {tf_user_api_private_key_file}: ")
    else:
        key_passphrase = None

    # upload api key to tf_user
    try:
        key_fingerprint = oci_wrapper.upload_api_key(
                            user=tf_user,
                            key_file=tf_user_api_private_key_file,
                            key_passphrase=key_passphrase)
    except pyhomelab.oci.exceptions.OCIAPIKeyUploadFailed as err:
        log.error(err)
        sys.exit(1)

    # update the config file with the tf-user
    tenancy_name = oci_wrapper.identity_client.get_tenancy(
                                                tenancy_id=oci_wrapper.config['tenancy']).data.name
    tf_user_config = OCIAPIProfile(user=tf_user.id,
                                   tenancy=oci_wrapper.config['tenancy'],
                                   region=oci_wrapper.config['region'],
                                   key=str(tf_user_api_private_key_file),
                                   fingerprint=key_fingerprint,
                                   log_level=args.log_level)
    tf_user_config.write_config(config_file=root_account_profile.config_file,
                                section=f"{tenancy_name}-{args.tf_user}")

    # create tf_group and add tf_user to group
    tf_group = oci_wrapper.create_group(name=args.tf_group,
                                        description='Terraform Users',
                                        freeform_tags={'infra': 'terraform'})
    oci_wrapper.add_user_to_group(group=tf_group, user=tf_user)

    # create tf_compartment
    tf_compartment = oci_wrapper.create_compartment(
                        name=args.tf_compartment,
                        description='Compartment to store Terraform created resources',
                        freeform_tags={'infra': 'terraform'})

    # create policy to only allow tf-group to admin tf-compartment
    create_policy = {
        'name': f"policy-{args.tf_group}",
        'statements': [
            (f"Allow group {tf_group.name} to manage all-resources "
             f"in compartment {tf_compartment.name}")
        ],
        'description': f"{args.tf_group} managed policies",
        'freeform_tags': {'infra': 'terraform'}
    }

    _ = oci_wrapper.create_policy(name=create_policy['name'],
                                  description=create_policy['description'],
                                  statements=create_policy['statements'],
                                  freeform_tags=create_policy['freeform_tags'])

    if args.create_tf_backend is False:
        log.success('DONE')
        sys.exit(0)

    # ######################
    # CONFIGURING TF BACKEND
    # ######################

    # create compartment to store resources that can be used in automation
    automation_compartment = oci_wrapper.create_compartment(
                                        name=args.automation_compartment,
                                        description='Compartment to store automation resources',
                                        freeform_tags=create_policy['freeform_tags'])

    # create vault
    vault = oci_wrapper.create_vault(name=args.vault_name,
                                     compartment=automation_compartment,
                                     freeform_tags={'infra': 'terraform'})

    # create vault key
    kms_key = oci_wrapper.create_vault_key(name=args.vault_key_name,
                                           vault=vault,
                                           compartment=automation_compartment,
                                           freeform_tags={'infra': 'terraform'})

    # updating policy
    create_policy['statements'] = [
        (f"Allow group {tf_group.name} to manage secret-family in compartment "
         f"{automation_compartment.name} where target.vault.id='{vault.id}'"),
        (f"Allow group {tf_group.name} to use vaults in compartment "
         f"{automation_compartment.name} where target.vault.id='{vault.id}'"),
        (f"Allow group {tf_group.name} to use keys in compartment "
         f"{automation_compartment.name} where target.key.id='{kms_key.id}'"),
        (f"Allow group {tf_group.name} to inspect secret in compartment "
         f"{automation_compartment.name}"),
        (f"Allow group {tf_group.name} to inspect vault in compartment "
         f"{automation_compartment.name}"),
        (f"Allow group {tf_group.name} to inspect keys in compartment "
         f"{automation_compartment.name} where target.vault.id='{vault.id}'")]
    _ = oci_wrapper.create_policy(name=create_policy['name'],
                                  description=create_policy['description'],
                                  statements=create_policy['statements'])

    log.success('DONE!')
    sys.exit(0)

if __name__ == '__main__':
    main()
