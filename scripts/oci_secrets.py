'''scripts/oci_secrets.py'''
import sys
import argparse
import subprocess
import textwrap
import oci
import pyhomelab.oci.exceptions
from pyhomelab.logger import logger
from pyhomelab.oci.profiles import OCIBrowserAuthProfile, OCIAPIConfigProfile
from pyhomelab.oci import OCIWrapper


def script_args() -> argparse.ArgumentParser:
    '''Script User Input Control'''

        # initialize the parser
    parser = argparse.ArgumentParser(description='OCI Vault Secret Management')

    group = parser.add_argument_group('General Options')
    group.add_argument('-v', dest='log_level', action='count', default=0,
                       help="Set log level (v - WARNING, vv - INFO, vvv - DEBUG)")
    group.add_argument('-c', '--config-file', dest='config_file', default='~/.oci/config',
                       help='The OCI configuration file to use (Default = ~/.oci/config)')

    group = parser.add_argument_group('OCI Account Options')
    group.add_argument('-p', '--profile', dest='profile', default='DEFAULT',
                       help='Profile to use in config-file (Default = DEFAULT)')
    group.add_argument('--auth', dest='auth_type', default='api',
                       choices=['security_token', 'api'],
                       help='Specify how to authenticate, Default = api')
    group.add_argument('-r', '--region', dest='region', default=None,
                       help='Required if --auth_type = security_token')

    group = parser.add_argument_group('Vault Options')
    group.add_argument('--compartment-name', dest='compartment_name',
                       default='compartment-automation',
                       help=textwrap.dedent('''
Name of the compartment the vault is in, Default = compartment-automation'''))
    group.add_argument('--vault-name', dest='vault-name', default='vault-automation-secrets',
                       help='Name of the vault that holds the secrets, Default = vault-automation')
    group.add_argument('--key-name', dest='key_name', default='key-secrets',
                       help='Name of the key in vault to encrypt secrets. Default = key-secrets')
    subparsers = parser.add_subparsers(description='Commands for oci_secrets.py', dest='subparser')

    # oci_secrets.py list
    subparsers.add_parser('list', description='List all the secrets',
                          formatter_class=argparse.RawTextHelpFormatter)

    # oci_secrets.py get
    subparser_get = subparsers.add_parser('get', description='Get secret value',
                                          formatter_class=argparse.RawTextHelpFormatter)
    subparser_get.add_argument('-n', '--name', dest='name', required=True, help='Name of secret')

    # oci_secrets.py set
    subparser_set = subparsers.add_parser('set', description='Set Secret',
                                        formatter_class=argparse.RawTextHelpFormatter)
    subparser_set.add_argument('-n', '--name', '--secret-name', dest='secret_name', required=True,
                               help='Name of the secret to create')
    subparser_set.add_argument('--value', dest='secret_value', default=None,
                               help=textwrap.dedent('''Secret Value, string or base64 encoded.
If not set, then prompt'''))
    subparser_set.add_argument('-d', '--description', default=None,
                               help='Secret description, default = None')

    # oci_secrets.py get
    subparser_delete = subparsers.add_parser('delete', description='Delete a secret',
                                          formatter_class=argparse.RawTextHelpFormatter)
    subparser_delete.add_argument('-n', '--name', dest='name', required=True,
                                  help='Name of secret to delete')

    return parser


def main() -> None:
    '''Main Control'''

    parser = script_args()
    args = parser.parse_args()

    if args.subparser is None:
        parser.print_help()
        sys.exit(0)

    # setting up logger
    log = logger(name='OCISecrets', log_level=args.log_level)

    log.trace("ARGS = %s", str(args))

    # setting up OCI wrapper
    if args.auth_type == 'security_token':
        if args.region is None:
            log.error('--region is required if auth_type == security_token')
            sys.exit(1)

        try:
            profile = OCIBrowserAuthProfile(name=args.profile,
                                            region=args.region,
                                            config_file=args.config_file,
                                            log_level=args.log_level)
        except subprocess.CalledProcessError as err:
            log.error(err)
            sys.exit(1)
    else:
        profile = OCIAPIConfigProfile(name=args.profile,
                                      config_file=args.config_file,
                                      log_level=args.log_level)

    try:
        oci_wrapper = OCIWrapper(profile=profile)
    except oci.exceptions.InvalidConfig as err:
        log.error("Profile %s in %s requires %s", args.profile, args.config_file, str(err))
        sys.exit(1)

    # get compartment
    try:
        compartment = oci_wrapper.get_compartments(name=args.compartment_name)[0]
    except IndexError:
        log.error("Compartment %s does not exist.", args.compartment_name)
        sys.exit(1)
    except pyhomelab.oci.exceptions.OCIAuthenticateError as err:
        log.error(err)
        sys.exit(1)

    # get vault
    try:
        vault = oci_wrapper.get_vaults(compartment=compartment)[0]
    except IndexError:
        log.error("No vault found in %s with name %s", compartment.name, args.vault_name)
        sys.exit(1)

    #
    # list secrets
    #
    if args.subparser == 'list':
        secrets = oci_wrapper.vault_list_secrets(compartment=compartment, vault=vault)
        for secret in secrets:
            print(f"Secret Name: {secret.secret_name} - {secret.lifecycle_state}")
        sys.exit(0)

    #
    # get secrets
    #
    elif args.subparser == 'get':
        try:
            secret = oci_wrapper.vault_list_secrets(compartment=compartment,
                                                    vault=vault,
                                                    name=args.name)[0]
        except IndexError:
            log.error("No secret found with name %s", args.name)
            sys.exit(1)

        try:
            secret_content = oci_wrapper.vault_get_secret(secret=secret)
        except pyhomelab.oci.exceptions.OCISecretDecryptionFailed as err:
            log.error(err)
            sys.exit(1)

        print(secret_content)
        sys.exit(0)

    #
    # set secrets
    #
    elif args.subparser == 'set':
        # get key
        try:
            key = oci_wrapper.list_vault_keys(compartment=compartment,
                                              vault=vault,
                                              algorithm='AES',
                                              name=args.key_name)[0]
        except IndexError:
            log.error("No vault key found with name %s", args.key_name)
            sys.exit(1)

        # set secret value
        if args.secret_value is None:
            secret_content = input(f"Enter value for {args.secret_name}: ")
        else:
            secret_content = args.secret_value

        try:
            secret = oci_wrapper.vault_set_secret(compartment=compartment,
                                                  vault=vault,
                                                  key=key,
                                                  secret_name=args.secret_name,
                                                  secret_content=secret_content)
        except pyhomelab.oci.exceptions.OCISecretUpdateFailed as err:
            log.error(err)
            sys.exit(1)
        sys.exit(0)

    #
    # delete secret
    #
    elif args.subparser == 'delete':
        try:
            oci_wrapper.vault_delete_secret(name=args.name,
                                            compartment=compartment,
                                            vault=vault)
        except (pyhomelab.oci.exceptions.OCISecretDoesNotExist,
                pyhomelab.oci.exceptions.OCISecretDeletionFailed) as err:
            log.error(err)
            sys.exit(1)

if __name__ == '__main__':
    main()
