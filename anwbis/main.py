"""
anwbis
-------------------------------
 - Eugenio Marinetto
 - nenetto@gmail.com
-------------------------------
Created 12-11-2018
"""

import argparse


def main():
    from anwbis.anwbis_utils import version
    from anwbis.anwbis_utils import Anwbis

    # CLI parser
    parser = argparse.ArgumentParser(description='AnWbiS: AWS Account Access')
    parser.add_argument('--version', action='version', version='%(prog)s' + version)
    parser.add_argument('--project', '-p', required=False, action='store',
                        help='MANDATORY (if you are not using --iam_master_group, --iam_policy and --iam_delegated_role): Project to connect',
                        default=False)
    parser.add_argument('--env', '-e', required=False, action='store',
                        help='MANDATORY (if you are not using --iam_master_group, --iam_policy and --iam_delegated_role): Set environment',
                        default=False,
                        choices=['dev', 'pre', 'prepro', 'pro', 'sbx', 'val', 'corp', 'qa', 'staging', 'demo', 'piloto',
                                 'test'])
    parser.add_argument('--role', '-r', required=False, action='store', help='Set role to use', default=False,
                        choices=['developer', 'devops', 'user', 'admin', 'audit', 'contractor'])
    parser.add_argument('--contractor', '-c', required=False, action='store',
                        help='Set role to use with contractor policies', default=False)
    parser.add_argument('--externalid', '-ext', required=False, action='store',
                        help='Set External-ID to use with contractor policies', default=False)
    parser.add_argument('--region', required=False, action='store', help='Set region for EC2', default=False,
                        choices=['eu-west-1', 'us-east-1', 'us-west-1', 'eu-central-1'])
    parser.add_argument('--nomfa', required=False, action='store_true', help='Disables Multi-Factor Authenticacion',
                        default=False)
    parser.add_argument('--refresh', required=False, action='store_true',
                        help='Refresh token even if there is a valid one', default=False)
    parser.add_argument('--browser', '-b', required=False, action='store', help='Set browser to use', default=False,
                        choices=['firefox', 'chrome', 'link', 'default', 'chromium'])
    parser.add_argument('--list', '-l', required=False, action='store', help='List available instances', default=False,
                        choices=['all', 'bastion'])
    parser.add_argument('--profile', '-P', required=False, action='store',
                        help='Optional: IAM credentials profile to use.', default=False)
    parser.add_argument('--duration', type=int, required=False, action='store',
                        help='Optional: Token Duration. Default=3600', default=3600)
    parser.add_argument('--iam_master_group', required=False, action='store',
                        help='MANDATORY (if you are not using -p -e and -r flags): Master account group name to use',
                        default=False)
    parser.add_argument('--iam_policy', required=False, action='store',
                        help='MANDATORY (if you are not using -p -e and -r flags): IAM Policy to use', default=False)
    parser.add_argument('--iam_delegated_role', required=False, action='store',
                        help='MANDATORY (if you are not using -p -e and -r flags): IAM delegated role to use',
                        default=False)
    parser.add_argument('--from_ec2_role', required=False, action='store_true',
                        help='Optional: use IAM role credentials stored in EC2 instead of users (advice: combine it with externalid)',
                        default=False)
    parser.add_argument('--get_session', required=False, action='store_true',
                        help='Optional: use STS get_session_token)', default=False)
    parser.add_argument('--stdout', required=False, action='store_true',
                        help='Optional: get export commands to set environment variables', default=False)
    parser.add_argument('--teleport', '-t', required=False, action='store', help='Teleport to instance', default=False)
    parser.add_argument('--filter', '-f', required=False, action='store', help='Filter instance name', default=False)
    parser.add_argument('--goodbye', '-g', required=False, action='store_true',
                        help='There are no easter eggs in this code, but AnWbiS can say goodbye', default=False)
    parser.add_argument('--verbose', '-v', action='store_true', help='prints verbosely', default=False)
    parser.add_argument('--project-tag', required=False, action='store',
                        help='Optional: Project tag for filtering instances', default='')
    parser.add_argument('--bastion-tag', required=False, action='store',
                        help='Optional: Bastion tag for filtering instances', default='Bastion')
    parser.add_argument('--name-tag', required=False, action='store',
                        help='Optional: Name tag for filtering instances', default='')

    args = parser.parse_args()

    _ = Anwbis(args)


if __name__ == "__main__":
    main()
