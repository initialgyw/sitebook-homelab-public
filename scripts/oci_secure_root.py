'''scripts/oci_secure_root.py'''
import sys
import argparse
import subprocess
import oci
import pyotp
from pyhomelab.logger import logger
from pyhomelab.oci.profiles import OCIBrowserAuthProfile
from pyhomelab.oci import OCIWrapper
from pyhomelab.shell import Shell


def script_args() -> argparse.ArgumentParser:
    '''Script User Input Control'''

    # initialize the parser
    parser = argparse.ArgumentParser(
                description='Secure OCI root account using auth_token (signing in via browser)')

    parser.add_argument('-v', dest='log_level', action='count', default=0,
                        help="Set log level (v - WARNING, vv - INFO, vvv - DEBUG, vvvv - TRACE)")
    parser.add_argument('-c', '--config-file', dest='config_file', default='~/.oci/config',
                        help='The OCI configuration file to use, Default = ~/.oci/config')
    parser.add_argument('-p', '--profile', dest='profile', default='DEFAULT',
                        help='Profile name to use in config-file. Default = DEFAULT')
    parser.add_argument('-t', '--tenancy', dest='tenancy', default=None,
                        help='Tenancy name for the account')
    parser.add_argument('-r', '--region', dest='region', required=True,
                        help='REQUIRED. Primary region for the account.')

    return parser


if __name__ == '__main__':
    args = script_args().parse_args()

    # setup logging
    log = logger(name='OCISecureRoot', log_level=args.log_level)
    log.trace("User inputs: %s", args)

    try:
        profile = OCIBrowserAuthProfile(name=args.profile,
                                        region=args.region,
                                        tenancy=args.tenancy,
                                        config_file=args.config_file,
                                        log_level=args.log_level)
    except subprocess.CalledProcessError as err:
        log.error(err.stdout)
        sys.exit(1)

    oci_wrapper = OCIWrapper(profile=profile)

    # get account user OCID
    try:
        users: list[oci.identity.models.user.User] = \
            oci_wrapper.identity_client.list_users(
                                            compartment_id=oci_wrapper.config['tenancy']).data
    except oci.exceptions.ServiceError:
        log.critical("""Provided profile (%s) in %s does not have permission to view users.
Are you sure this is a root account?""", profile.name, profile.config_file)
        sys.exit(1)

    account_owner: oci.identity.models.user.User = users[0]

    # check mfa status
    if account_owner.is_mfa_activated is True:
        log.success("%s account MFA is already active", account_owner.name)
        sys.exit(0)

    # list account TOTP
    try:
        # oci.identity.models.mfa_totp_device_summary.MfaTotpDeviceSummary
        mfa_totp_device = oci_wrapper.identity_client.list_mfa_totp_devices(
                                                        user_id=account_owner.id, ).data[0]
        log.trace("MFA device already exists: %s", mfa_totp_device.id)
    except IndexError:
        log.info("No TOTP Device found for %s. Creating one.", account_owner.name)
        mfa_totp_device = oci_wrapper.identity_client.create_mfa_totp_device(
                                                        user_id=account_owner.id).data
        log.success("MFA created: %s", mfa_totp_device.id)


    if 'seed' not in mfa_totp_device.__dict__:
        mfa_totp_device_seed = oci_wrapper.identity_client.generate_totp_seed(
                                        user_id=account_owner.id,
                                        mfa_totp_device_id=mfa_totp_device.id).data.seed
    else:
        mfa_totp_device_seed = mfa_totp_device.seed

    sys.stdout.write(Shell.TERMCOLORS['RED'])
    print('*' * 50)
    print(f'SAVE THIS SECRET: {mfa_totp_device_seed}')
    print('*' * 50)
    sys.stdout.write(Shell.TERMCOLORS['RESET'])

    # generate the one-time token and activate the MFA device
    totp = pyotp.TOTP(mfa_totp_device_seed)
    _ = oci_wrapper.identity_client.activate_mfa_totp_device(
                        user_id=account_owner.id,
                        mfa_totp_device_id=mfa_totp_device.id,
                        mfa_totp_token=oci.identity.models.MfaTotpToken(totp_token=totp.now()))


    log.success('DONE')
