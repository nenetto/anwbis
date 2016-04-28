#!/usr/bin/env python
import argparse
import requests # "pip install requests"
import sys, os, urllib, json, webbrowser
import hashlib
import re
import os
import json
import time
from boto.sts import STSConnection # AWS Python SDK--"pip install boto"
from boto.iam import IAMConnection
from boto import ec2
from colorama import init, Fore, Back, Style
from requests.packages.urllib3 import disable_warnings

#             __          ___     _  _____
#     /\      \ \        / / |   (_)/ ____|
#    /  \   _ _\ \  /\  / /| |__  _| (___
#   / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \
#  / ____ \| | | \  /\  /  | |_) | |____) |
# /_/    \_\_| |_|\/  \/   |_.__/|_|_____/
#
#          Amazon Account Access

version = '1.5.0'

# CLI parser
parser = argparse.ArgumentParser(description='AnWbiS: AWS Account Access')
parser.add_argument('--version', action='version', version='%(prog)s'+version)
parser.add_argument('--project', '-p', required=False, action = 'store', help = 'MANDATORY (if you are not using --iam_master_group, --iam_policy and --iam_delegated_role): Project to connect', default=False)
parser.add_argument('--env', '-e', required=False, action = 'store', help = 'MANDATORY (if you are not using --iam_master_group, --iam_policy and --iam_delegated_role): Set environment', default=False,
        choices=['dev', 'pre', 'prepro', 'pro', 'sbx', 'val', 'corp', 'qa', 'staging', 'demo'])
parser.add_argument('--role', '-r', required=False, action = 'store', help = 'Set role to use', default=False,
        choices=['developer', 'devops', 'user', 'admin', 'audit', 'contractor'])
parser.add_argument('--contractor', '-c', required=False, action = 'store', help = 'Set role to use with contractor policies', default=False)
parser.add_argument('--externalid', '-ext', required=False, action = 'store', help = 'Set External-ID to use with contractor policies', default=False)
parser.add_argument('--region', required=False, action = 'store', help = 'Set region for EC2', default=False,
        choices=['eu-west-1', 'us-east-1', 'us-west-1'])
parser.add_argument('--nomfa', required=False, action='store_true', help='Disables Multi-Factor Authenticacion', default=False)
parser.add_argument('--refresh', required=False, action='store_true', help='Refresh token even if there is a valid one', default=False)
parser.add_argument('--browser', '-b', required=False, action = 'store', help = 'Set browser to use', default=False,
            choices=['firefox','chrome','link','default', 'chromium'])
parser.add_argument('--list', '-l', required=False, action = 'store', help = 'List available instances', default=False,
        choices=['all', 'bastion'])
parser.add_argument('--profile', '-P', required=False, action = 'store', help = 'Optional: IAM credentials profile to use.', default=False)
parser.add_argument('--duration', type=int, required=False, action = 'store', help = 'Optional: Token Duration. Default=3600', default=3600)
parser.add_argument('--iam_master_group', required=False, action = 'store', help = 'MANDATORY (if you are not using -p -e and -r flags): Master account group name to use', default=False)
parser.add_argument('--iam_policy', required=False, action = 'store', help = 'MANDATORY (if you are not using -p -e and -r flags): IAM Policy to use', default=False)
parser.add_argument('--iam_delegated_role', required=False, action = 'store', help = 'MANDATORY (if you are not using -p -e and -r flags): IAM delegated role to use', default=False)
parser.add_argument('--from_ec2_role', required=False, action='store_true', help='Optional: use IAM role credentials stored in EC2 instead of users (advice: combine it with externalid)', default=False)
parser.add_argument('--get_session', required=False, action='store_true', help='Optional: use STS get_session_token)', default=False)
parser.add_argument('--stdout', required=False, action='store_true', help='Optional: get export commands to set environment variables', default=False)
parser.add_argument('--teleport', '-t', required=False, action = 'store', help = 'Teleport to instance', default=False)
parser.add_argument('--filter', '-f', required=False, action = 'store', help = 'Filter instance name', default=False)
parser.add_argument('--goodbye', '-g', required=False, action='store_true', help = 'There are no easter eggs in this code, but AnWbiS can say goodbye', default=False)
parser.add_argument('--verbose', '-v', action = 'store_true', help = 'prints verbosely', default=False)
parser.add_argument('--project-tag', required=False, action='store',
                    help='Optional: Project tag for filtering instances', default='')
parser.add_argument('--bastion-tag', required=False, action='store',
                    help='Optional: Bastion tag for filtering instances', default='Bastion')
parser.add_argument('--name-tag', required=False, action='store',
                    help='Optional: Name tag for filtering instances', default='')


args = parser.parse_args()

def verbose(msg):
    if args.verbose:
        print (Fore.BLUE + ''.join(map(str, (msg))))
        print (Fore.RESET + Back.RESET + Style.RESET_ALL)

def colormsg(msg,mode):
    print ""
    if mode == 'ok':
        print (Fore.GREEN + '[ OK ] ' + ''.join(map(str, (msg))))
        print (Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'error':
        print (Fore.RED + '[ ERROR ] ' + ''.join(map(str, (msg))))
        print (Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'normal':
        print (Fore.WHITE + ''.join(map(str, (msg))))
        print (Fore.RESET + Back.RESET + Style.RESET_ALL)

def sha256(m):
    return hashlib.sha256(m).hexdigest()

def config_line(header, name, detail, data):
    return header + ", " + name + ", " + detail + ", " + data

def config_line_policy(header, name, detail, data):
    verbose("===== " + header + ":  " + name + ":  " + detail + "=====")
    verbose(data)
    verbose("=========================================================")
    return config_line(header, name, detail, sha256(data))

def output_lines(lines):
    lines.sort()
    for line in lines:
        print line

def list_function(list_instances, access_key, session_key, session_token, regions):

    try:
        ec2_conn = ec2.connect_to_region(region,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=session_key,
                    security_token=session_token)
    except Exception, e:
        colormsg ("There was an error connecting to EC2", "error")
        verbose(e)
        exit(1)

    reservations = ec2_conn.get_all_reservations(filters={"tag:Name" : "*"+filter_name+"*"})

    bastions = []

    try:
        if len(reservations) > 0:
            if list_instances == 'all' or list_instances == 'bastion':
                layout="{!s:60} {!s:15} {!s:15} {!s:15} {!s:15}"
                headers=["Name","Project","Bastion","IP Address","Instance-Id","Status"]
                colormsg(region+":","normal")
                print layout.format(*headers)

            for reservation in reservations:
                for instance in reservation.instances:
                    if instance.state == "running":
                        if instance.ip_address == None:
                            ip = instance.private_ip_address
                        else:
                            ip = instance.ip_address

                        if list_instances == 'all' and args.bastion_tag not in instance.tags:
                            print layout.format(instance.tags['Name'], instance.tags[args.project_tag] if args.project_tag in instance.tags else "N/A", 'N/A', ip, instance.id, instance.state)
                        elif list_instances == 'all' or list_instances == 'bastion' and args.bastion_tag in instance.tags:
                            print layout.format(instance.tags['Name'], instance.tags[args.project_tag] if args.project_tag in instance.tags else "N/A", instance.tags[args.bastion_tag], ip, instance.id, instance.state)
                            bastions.append(ip)
                        elif list_instances == 'teleport' and args.bastion_tag in instance.tags and instance.tags[args.bastion_tag].lower()=='true':
                            bastions.append(ip)

            return bastions
        else:
            colormsg("There are no instances for your project in the region "+region, "error")
            exit(1)
    except Exception, e:
        colormsg ("There was an error while listing EC2 instances", "error")
        verbose(e)
        exit(1)

def save_credentials(access_key,  session_key,  session_token, role_session_name, project_name, environment_name,
                     role_name, region, local_file_path="~/.anwbis"):
    """
    Persists temporal credentials in a local file
    :param access_key: Access Key Id
    :param session_key: Secret Key
    :param session_token: Temporal token
    :param role_session_name: Session role name
    :param project_name: Project
    :param environment_name: Environment (dev, pro, pre...)
    :param role_name: Role name
    :param region: Default region
    """
    if os.path.isfile(os.path.expanduser(local_file_path)):

        with open(os.path.expanduser(local_file_path), 'r') as json_file:
            json_file.seek(0)
            root_json_data = json.load(json_file)
            json_file.close()

        with open(os.path.expanduser(local_file_path), 'w+') as json_file:
            if project_name not in root_json_data:
                root_json_data[project_name] = {}
            if environment_name not in root_json_data[project_name]:
                root_json_data[project_name][environment_name] = {}
            if role_name not in root_json_data[project_name][environment_name]:
                root_json_data[project_name][environment_name][role_name] = {}

            root_json_data[project_name][environment_name][role_name]["anwbis_last_timestamp"] = str(int(time
                                                                                                             .time()))
            root_json_data[project_name][environment_name][role_name]["access_key"] = access_key
            root_json_data[project_name][environment_name][role_name]["role_session_name"] = role_session_name
            root_json_data[project_name][environment_name][role_name]["session_key"] = session_key
            root_json_data[project_name][environment_name][role_name]["session_token"] = session_token
            root_json_data[project_name][environment_name][role_name]["region"] = region
            json.dump(root_json_data, json_file)
    else:
        with open(os.path.expanduser(local_file_path), 'w+') as json_file:
            data = {
                project_name: {
                    environment_name: {
                        role_name: {
                            "anwbis_last_timestamp": str(int(time.time())),
                            "access_key": access_key,
                            "role_session_name": role_session_name,
                            "session_key": session_key,
                            "session_token": session_token,
                            "region": region
                        }
                    }
                }
            }
            json.dump(data, json_file)

def get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project_name, environment_name, role_name, token_expiration):
    try:

        if not args.nomfa:
            mfa_token = raw_input("Enter the MFA code: ")
            if args.externalid:
                assumed_role_object = sts_connection.assume_role(
                    role_arn=role_arn,
                    role_session_name=role_session_name,
                    duration_seconds=token_expiration,
                    mfa_serial_number=mfa_serial_number,
                    mfa_token=mfa_token,
                    external_id=externalid
                )
            else:
                assumed_role_object = sts_connection.assume_role(
                    role_arn=role_arn,
                    role_session_name=role_session_name,
                    duration_seconds=token_expiration,
                    mfa_serial_number=mfa_serial_number,
                    mfa_token=mfa_token
                )

        else:
            mfa_token = None
            if args.externalid:
                assumed_role_object = sts_connection.assume_role(
                    role_arn=role_arn,
                    role_session_name=role_session_name,
                    duration_seconds=token_expiration,
                    external_id=externalid
                )
            else:
                assumed_role_object = sts_connection.assume_role(
                    role_arn=role_arn,
                    role_session_name=role_session_name,
                    duration_seconds=token_expiration,
                )

    except Exception, e:
        colormsg ("There was an error assuming role", "error")
        verbose(e)
        exit(1)

    colormsg ("Assumed the role successfully", "ok")

    # Format resulting temporary credentials into a JSON block using
    # known field names.

    access_key = assumed_role_object.credentials.access_key
    session_key = assumed_role_object.credentials.secret_key
    session_token = assumed_role_object.credentials.session_token

    login_to_fedaccount(access_key, session_key, session_token, role_session_name)

    save_credentials(access_key, session_key, session_token, role_session_name, project_name, environment_name, role_name, region)

    #and save them on the CLI config file .aws/credentials

    save_cli_credentials(access_key, session_key, session_token, '-'.join([project_name, environment_name, role_name]), region)

    if args.stdout:
        print ""
        print "If you want to use your credentials from the environment with an external Tool (for instance, Terraform), you can use the following instructions:"
        print "WARNING: If you use it in the same shell as anwbis exported variables takes precedence over the .aws/credentials, so use it carefully"
        print ""
        print "export AWS_ACCESS_KEY_ID='%s'" % access_key
        print "export AWS_SECRET_ACCESS_KEY='%s'" % session_key
        print "export AWS_SESSION_TOKEN='%s'" % session_token
        print "export AWS_DEFAULT_REGION='%s'" % region
        print ""

    return { 'access_key':access_key, 'session_key': session_key, 'session_token': session_token, 'role_session_name': role_session_name }

def get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project_name, environment_name, role_name, token_expiration):
    try:

        if not args.nomfa:
            mfa_token = raw_input("Enter the MFA code: ")
            sts_session = sts_connection.get_session_token(
                duration=token_expiration,
                mfa_serial_number=mfa_serial_number,
                mfa_token=mfa_token
            )

            session_sts_connection = STSConnection(aws_access_key_id=sts_session.access_key,
                                                   aws_secret_access_key=sts_session.secret_key,
                                                   security_token=sts_session.session_token)

            if args.externalid:
                assumed_role_object = session_sts_connection.assume_role(
                    role_arn=role_arn,

                    role_session_name=role_session_name,
                    duration_seconds=token_expiration,
                    external_id=externalid
                )
            #else:
                #assumed_role_object = session_sts_connection.assume_role(
                #    role_arn=role_arn,
                #    role_session_name=role_session_name,
                #    duration_seconds=token_expiration,
                #)
        else:
             colormsg ("When using get_session you must use MFA", "error")
             exit(1)

    except Exception, e:
        colormsg ("There was an error assuming role", "error")
        verbose(e)
        exit(1)

    colormsg ("Assumed the role successfully", "ok")

    # Format resulting temporary credentials into a JSON block using
    # known field names.
    access_key = sts_session.access_key
    session_key = sts_session.secret_key
    session_token = sts_session.session_token
    expiration = sts_session.expiration

    login_to_fedaccount(access_key, session_key, session_token, role_session_name)

    save_credentials(access_key, session_key, session_token, role_session_name, "session-"+project_name, environment_name, role_name, region)

    save_credentials(access_key, session_key, session_token, role_session_name, project_name, environment_name, role_name, region)

    #and save them on the CLI config file .aws/credentials

    save_cli_credentials(access_key, session_key, session_token, '-'.join(["session-"+project_name, environment_name, role_name]), region)

    if args.stdout:
        print ""
        print "If you want to use your credentials from the environment with an external Tool (for instance, Terraform), you can use the following instructions:"
        print "WARNING: If you use it in the same shell as anwbis exported variables takes precedence over the .aws/credentials, so use it carefully"
        print ""
        print "export AWS_ACCESS_KEY_ID='%s'" % access_key
        print "export AWS_SECRET_ACCESS_KEY='%s'" % session_key
        print "export AWS_SESSION_TOKEN='%s'" % session_token
        print "export AWS_DEFAULT_REGION='%s'" % region
        print "Expiration='%s'" % expiration
        print ""

    return { 'access_key':access_key, 'session_key': session_key, 'session_token': session_token, 'role_session_name': role_session_name }

def save_cli_credentials(access_key, session_key, session_token, section_name, region):

    import ConfigParser
    import os

    config = ConfigParser.RawConfigParser()
    home = os.path.expanduser("~")
    basedir = os.path.dirname(home+'/.aws/credentials')
    if not os.path.exists(basedir):
        os.makedirs(basedir)
    if not os.path.isfile(home+'/.aws/credentials'):
        verbose("There is no ~/.aws/credentials (probably using an EC2 instance profile. Creating credentials file...")
        open(home+'/.aws/credentials', 'a').close() 
    config.read(os.path.expanduser('~/.aws/credentials'))

    if not config.has_section(section_name):
        config.add_section(section_name)

    config.set(section_name, 'aws_access_key_id', access_key)
    config.set(section_name, 'aws_secret_access_key', session_key)
    config.set(section_name, 'aws_session_token', session_token)
    config.set(section_name, 'aws_security_token', session_token)
    config.set(section_name, 'region', region)

    # Writing our configuration file to 'example.cfg'
    with open(os.path.expanduser('~/.aws/credentials'), 'wb') as configfile:
        config.write(configfile)

def login_to_fedaccount(access_key, session_key, session_token, role_session_name):

    json_temp_credentials = '{'
    json_temp_credentials += '"sessionId":"' + access_key + '",'
    json_temp_credentials += '"sessionKey":"' + session_key + '",'
    json_temp_credentials += '"sessionToken":"' + session_token + '"'
    json_temp_credentials += '}'

    # Make a request to the AWS federation endpoint to get a sign-in
    # token, passing parameters in the query string. The call requires an
    # Action parameter ('getSigninToken') and a Session parameter (the
    # JSON string that contains the temporary credentials that have
    # been URL-encoded).
    request_parameters = "?Action=getSigninToken"
    request_parameters += "&Session="
    request_parameters += urllib.quote_plus(json_temp_credentials)
    request_url = "https://signin.aws.amazon.com/federation"
    request_url += request_parameters
    r = requests.get(request_url)

    # Get the return value from the federation endpoint--a
    # JSON document that has a single element named 'SigninToken'.
    sign_in_token = json.loads(r.text)["SigninToken"]

    # Create the URL that will let users sign in to the console using
    # the sign-in token. This URL must be used within 15 minutes of when the
    # sign-in token was issued.
    request_parameters = "?Action=login"
    request_parameters += "&Issuer=" + role_session_name
    request_parameters += "&Destination="
    request_parameters += urllib.quote_plus("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + sign_in_token
    request_url = "https://signin.aws.amazon.com/federation"
    request_url += request_parameters

    # Easter Egg: Say Hello
    if args.goodbye:
        print ""
        print "          .. ..              ..."
        print "        .' ;' ;             ;''''."
        print "        ;| ; |;            ;;    ;"
        print "        ;| ; |;            ;;.   ;"
        print "        ;  ~~~~',,,,,,,    '. '  ;"
        print "        ;    -A       ;      ';  ;"
        print "        ;       .....'        ;   ;"
        print "        ;      _;             ;   ;"
        print "        ;   __(o)__.          ;   ;"
        print "       .;  '\--\\--\        .'    ;"
        print "     .'\ \_.._._\\......,.,.;     ;"
        print "  .''   |       ;   ';      '    .'"
        print " ;      |      .'    ;..,,.,,,,.'"
        print " ;      |    .'  ...'"
        print " '.     \  .'   ,'  \\"
        print "   '.    ;'   .;     \\"
        print "     '.      .'      '-'"
        print "       '..  .'"
        print "          '''"
        print ""
        print "  Thanks for using AnWbiS. Goodbye!"
        print ""

    # Use the browser to sign in to the console using the
    # generated URL.
    chrome_path = '/usr/bin/google-chrome %s'
    firefox_path = '/usr/bin/firefox %s'
    chromium_path = '/usr/bin/chromium %s'
    if browser == 'firefox':
        try:
            webbrowser.get(firefox_path).open(request_url)
        except Exception, e:
            colormsg ("There was an error while open your browser", "error")
            verbose(e)
            exit(1)
    elif browser == 'chrome':
        try:
            webbrowser.get(chrome_path).open(request_url)
        except Exception, e:
            colormsg ("There was an error while open your browser", "error")
            verbose(e)
            exit(1)
    elif browser == 'chromium':
        try:
            webbrowser.get(chromium_path).open(request_url)
        except Exception, e:
            colormsg ("There was an error while open your browser", "error")
            verbose(e)
            exit(1)
    elif browser == 'default':
        try:
            webbrowser.open(request_url)
        except Exception, e:
            colormsg ("There was an error while open your browser", "error")
            verbose(e)
            exit(1)
    elif browser == 'link':
        colormsg(request_url,"normal")
    #else:
    #    webbrowser.open(request_url)

    # List parser for listing instances



# END FUNCTIONS SECTION
class Anwbis:
    disable_warnings()
    def token(self):
        global region
        global role
        global externalid
        global browser
        global access_key
        global session_key
        global session_token



        # Welcome
        if args.verbose:
            print ""
            print "             __          ___     _  _____ "
            print "     /\      \ \        / / |   (_)/ ____|"
            print "    /  \   _ _\ \  /\  / /| |__  _| (___  "
            print "   / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \ "
            print "  / ____ \| | | \  /\  /  | |_) | |____) |"
            print " /_/    \_\_| |_|\/  \/   |_.__/|_|_____/ "
            print ""
            print "       Amazon Account Access "+ version
            print ""

        else:
            print ""
            print "AnWbiS Amazon Account Access "+ version
            print ""

        # Set values from parser

        if not args.project or not args.env:
            if not args.iam_master_group or not args.iam_policy or not args.iam_delegated_role and not args.from_ec2_role:
                colormsg("You must provide either -p and -e flags or --iam_master_group, --iam_policy and --iam_delegated_role to use Anwbis", "error")
                exit(1)
            elif args.from_ec2_role and not args.iam_delegated_role:
                colormsg("When using credentials stored in EC2 roles you must use either -p and -e flags or --iam_delegated_role to use Anwbis", "error")
                exit(1)
        if args.role:
            if args.role == 'contractor' and not args.contractor:
                colormsg ("When using role contractor you must provide --contractor (-c) flag with the contractor policy to asume", "error")
                exit(1)
            elif args.role == 'contractor' and args.contractor and not args.externalid:
                colormsg ("When using role contractor you must provide --externalid (-ext) code with the ExternalID to use", "error")
                exit(1)
            elif args.role == 'contractor' and args.contractor and args.externalid:
                role = args.role+'-'+args.contractor
                verbose("Asuming contractor role: "+ args.role+'-'+args.contractor)
            else:
                role = args.role
        elif args.iam_delegated_role:
            role = args.iam_delegated_role
        else:
            role = 'developer'

        if args.profile:
            profile_name = args.profile

        if args.region:
            region = args.region
        else:
            region = 'eu-west-1'

        if args.project:
            project = args.project
            project = project.lower()
            verbose("Proyect: "+project)

        if args.env:
            env = args.env
            env = env.lower()
            verbose("Environment: "+env)

        if args.browser:
            browser = args.browser
        else:
            browser = 'none'

        if args.duration > 3600:
            if not args.get_session:
                token_expiration=3600
            elif args.duration > 129600:
                token_expiration=129600
        elif args.duration < 900:
            token_expiration=900
        else:
            token_expiration=args.duration

        if args.externalid:
            externalid = args.externalid


        # Get Corp Account ID and set session name

        if args.profile:
            iam_connection = IAMConnection(profile_name=args.profile)
        else:
            iam_connection = IAMConnection()

        #role_session_name=iam_connection.get_user()['get_user_response']['get_user_result']['user']['user_name']
        try:
            if args.from_ec2_role:
                request_url = "http://169.254.169.254/latest/meta-data/iam/info/"
                r = requests.get(request_url)
                profilearn=json.loads(r.text)["InstanceProfileArn"]
                profileid=json.loads(r.text)["InstanceProfileId"]
                profilename=json.loads(r.text)["InstanceProfileArn"].split('/')[1]
                role_session_name=profilename
            else:
                role_session_name=iam_connection.get_user().get_user_response.get_user_result.user.user_name
        except Exception, e:
            colormsg ("There was an error retrieving your session_name. Check your credentials", "error")
            verbose(e)
            exit(1)

        #account_id=iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]
        try:
            if args.from_ec2_role:
                account_id=profilearn=json.loads(r.text)["InstanceProfileArn"].split(':')[4]
                account_id_from_user=account_id
                role_name_from_user=profilename
            else:
                account_id=iam_connection.get_user().get_user_response.get_user_result.user.arn.split(':')[4]
        except Exception, e:
            colormsg ("There was an error retrieving your account id. Check your credentials", "error")
            verbose(e)
            exit(1)

        # Regexp for groups and policies. Set the policy name used by your organization

        if args.project and args.env:
            if not args.from_ec2_role:
                group_name='corp-'+project+'-master-'+role
                policy_name='Delegated_Roles'
                role_filter=env+'-'+project+'-delegated-'+role
            else:
                group_name='IAM EC2 ROLE'
                policy_name='Delegated_Roles'
                role_filter=env+'-'+project+'-delegated-'+role

        # Get rid of the standard for using another policies or group names
        elif args.from_ec2_role and args.iam_delegated_role:
            role_filter=args.iam_delegated_role
            # Fix references to project, env and role in .anwbis file for non-standard use
            role=role_filter
            project=group_name
            env="ec2-role"
        elif args.iam_master_group and args.iam_policy and args.iam_delegated_role:
            group_name=args.iam_master_group
            policy_name=args.iam_policy
            role_filter=args.iam_delegated_role
            # Fix references to project, env and role in .anwbis file for non-standard use
            role=role_filter
            project=group_name
            env=policy_name


        # Step 1: Prompt user for target account ID and name of role to assume

        # IAM groups
        verbose("Getting IAM group info:")
        delegated_policy = []
        group_policy = []
        delegated_arn = []

        try:
            if not args.from_ec2_role:
                policy = iam_connection.get_group_policy( group_name, policy_name)
            else:
                #policy = iam_connection.get_instance_profile(profilename)
                policy = iam_connection.get_role_policy (profilename,policy_name)
        except Exception, e:
            colormsg ("There was an error retrieving your group policy. Check your credentials, group_name and policy_name", "error")
            verbose(e)
            exit(1)

        if not args.from_ec2_role:
            policy = policy.get_group_policy_response.get_group_policy_result.policy_document
            policy = urllib.unquote(policy)
            group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

        else:
            policy = policy.get_role_policy_response.get_role_policy_result.policy_document
            policy = urllib.unquote(policy)
            group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

        output_lines(group_policy)

        # Format policy and search by role_filter

        policy = re.split('"', policy)

        for i in policy:
            result_filter = re.search (role_filter, i)
            if result_filter:
                delegated_arn.append(i)

        if len(delegated_arn) == 0:
            if args.role and args.project:
                colormsg ("Sorry, you are not authorized to use the role "+role+" for project "+project, "error")
                exit(1)
            else:
                colormsg ("Sorry, you are not authorized to use the role "+role_filter, "error")
                exit(1)

        elif len(delegated_arn) == 1:
            account_id_from_user = delegated_arn[0].split(':')[4]
            role_name_from_user = delegated_arn[0].split('/')[1]

        else:
            colormsg("There are two or more policies matching your input", "error")
            exit(1)


        colormsg("You are authenticated as " + role_session_name, "ok")

        #MFA
        if not args.nomfa:
            mfa_devices_r = iam_connection.get_all_mfa_devices(role_session_name)
            if  mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices:
                mfa_serial_number =  mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices[0].serial_number
            else:
                colormsg("You don't have MFA devices associated with our user", "error")
                exit(1)
        else:
            mfa_serial_number = "arn:aws:iam::"+account_id+":mfa/"+role_session_name

        # Create an ARN out of the information provided by the user.
        role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
        role_arn += role_name_from_user

        # Connect to AWS STS and then call AssumeRole. This returns temporary security credentials.
        if args.profile:
            sts_connection = STSConnection(profile_name=args.profile)
        else:
            sts_connection = STSConnection()

        # Assume the role
        if not args.nomfa:
            verbose("Assuming role "+ role_arn+ " using MFA device " + mfa_serial_number + "...")
            if args.project:
                colormsg("Assuming role "+ role+ " from project "+ project+ " using MFA device from user "+ role_session_name+ "...", "normal")
            elif args.iam_delegated_role:
                colormsg("Assuming role "+ role+ " using MFA device from user "+ role_session_name+ "...", "normal")
        else:
            verbose("Assuming role "+ role_arn+ "...")
            if args.project:
                colormsg("Assuming role "+ role+ " from project "+ project+ " from user "+ role_session_name+ "...", "normal")
            elif args.iam_delegated_role:
                colormsg("Assuming role "+ role+ " from user "+ role_session_name+ "...", "normal")


        if os.path.isfile(os.path.expanduser('~/.anwbis')):
            with open(os.path.expanduser('~/.anwbis')) as json_file:
                root_json_data = json.load(json_file)
                json_file.close()

                if project in root_json_data and env in root_json_data[project] and role in root_json_data[project][env]:
                    json_data = root_json_data[project][env][role]
                    anwbis_last_timestamp = json_data["anwbis_last_timestamp"]

                    #check if the token has expired
                    if int(time.time()) - int(anwbis_last_timestamp) > token_expiration or args.refresh:

                        #print "token has expired"
                        if not args.get_session:
                            sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)
                        else:
                            sts_token = get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)

                    else:
                        #print "token has not expired, trying to login..."
                        login_to_fedaccount(json_data["access_key"], json_data["session_key"], json_data["session_token"], json_data["role_session_name"])
                        sts_token = {'access_key':json_data["access_key"], 'session_key':json_data["session_key"], 'session_token': json_data["session_token"], 'role_session_name': json_data["role_session_name"]}

                else:
                    if not args.get_session:
                        sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)
                    else:
                        sts_token = get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)

        else:
            #print ".anwbis configuration file doesnt exists"
            verbose("role is " +  role)
            if not args.get_session:
                sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)
            else:
                sts_token = get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env, role, token_expiration)

        return sts_token

    def controller(self):

        global browser
        global list_instances

        if args.list:
            list_instances = args.list
            if args.filter:
                filter_name=args.filter
        else:
            list_instances = 'none'

        if args.teleport:
            teleport_instance = args.teleport
            if args.filter:
                filter_name=args.filter
        else:
            teleport = 'none'

        if args.list:
            list_function(list_instances, access_key, session_key, session_token, region)

        # Teleport parser for connecting to bastion

        if args.teleport:
            bastions = list_function('teleport', access_key, session_key, session_token)
            if len(bastions) == 0:
                colormsg("Sorry, there are no bastions to connect in project "+project+" for the environment "+env, "error")
            elif len(bastions) == 1:
                for i in bastions:
                    print i
            else:
                colormsg("There are more than one bastion in project "+project+" for the environment "+env, "normal")
                list_function('bastion')
                colormsg("You can connect to the desired bastion using -t <IP> (--teleport <IP>)", "normal")


    #Runs all the functions
    def __init__(self):
        global access_key
        global session_key
        global session_token
        token = self.token()
        access_key = token['access_key']
        session_key = token['session_key']
        session_token = token['session_token']
        self.controller()
        exit(0)

#This idiom means the below code only runs when executed from command line

if __name__ == '__main__':
    a = Anwbis()
