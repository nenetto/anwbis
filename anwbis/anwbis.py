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

#             __          ___     _  _____
#     /\      \ \        / / |   (_)/ ____|
#    /  \   _ _\ \  /\  / /| |__  _| (___
#   / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \
#  / ____ \| | | \  /\  /  | |_) | |____) |
# /_/    \_\_| |_|\/  \/   |_.__/|_|_____/
#
#          Amazon Account Access

version = '1.1.5-SNAPSHOT'

# Regions to use with teleport
#regions = ['us-east-1', 'us-west-1', 'eu-west-1']

# Project tag for filtering instances
project_tag = 'Proyecto'
bastion_tag = 'Bastion'

# Filter by tag (for when args.filter is not defined)
filter_name = ''

# CLI parser

parser = argparse.ArgumentParser(description='AnWbiS: AWS Account Access')
parser.add_argument('--version', action='version', version='%(prog)s'+version)
parser.add_argument('--project', '-p', required=True, action = 'store', help = 'MANDATORY: Project to connect', default=False)
parser.add_argument('--env', '-e', required=True, action = 'store', help = 'MANTATORY: Set environment', default=False,
        choices=['dev', 'pre', 'pro', 'sbx', 'val', 'corp'])
parser.add_argument('--role', '-r', required=False, action = 'store', help = 'Set role to use', default=False,
        choices=['developer', 'admin'])
parser.add_argument('--region', required=False, action = 'store', help = 'Set region for EC2', default=False,
        choices=['eu-west-1', 'us-east-1', 'us-west-1'])
parser.add_argument('--browser', '-b', required=False, action = 'store', help = 'Set browser to use', default=False,
        choices=['firefox','chrome','link','default'])
parser.add_argument('--list', '-l', required=False, action = 'store', help = 'List available instances', default=False,
        choices=['all', 'bastion'])
parser.add_argument('--profile', '-P', required=False, action = 'store', help = 'Optional: IAM credentials profile to use.', default=False)
parser.add_argument('--teleport', '-t', required=False, action = 'store', help = 'Teleport to instance', default=False)
parser.add_argument('--filter', '-f', required=False, action = 'store', help = 'Filter instance name', default=False)
parser.add_argument('--goodbye', '-g', required=False, action='store_true', help = 'There are no easter eggs in this code, but AnWbiS can say goodbye', default=False)
parser.add_argument('--verbose', '-v', action = 'store_true', help = 'prints verbosely', default=False)


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

                        if list_instances == 'all' and bastion_tag not in instance.tags:
                            print layout.format(instance.tags['Name'], instance.tags[project_tag] if project_tag in instance.tags else "N/A", 'N/A', ip, instance.id, instance.state)
                        elif list_instances == 'all' or list_instances == 'bastion' and bastion_tag in instance.tags:
                            print layout.format(instance.tags['Name'], instance.tags[project_tag] if project_tag in instance.tags else "N/A", instance.tags[bastion_tag], ip, instance.id, instance.state)
                            bastions.append(ip)
                        elif list_instances == 'teleport' and bastion_tag in instance.tags and instance.tags[bastion_tag].lower()=='true':
                            bastions.append(ip)

            return bastions
        else:
            colormsg("There are no instances for your project in the region "+region, "error")
            exit(1)
    except Exception, e:
        colormsg ("There was an error while listing EC2 instances", "error")
        verbose(e)
        exit(1)

def save_credentials(access_key,  session_key,  session_token, role_session_name, project_name, environment_name, role_name):

    #print "trying..."
    if os.path.isfile(os.path.expanduser('~/.anwbis')):
        with open(os.path.expanduser('~/.anwbis'), 'r') as json_file:
            #print "fin contenido..."
            json_file.seek(0)
            root_json_data = json.load(json_file)
            #print json.dumps(root_json_data)
            json_file.close()
            #print json.dumps(root_json_data)
            json_file = None
            with open(os.path.expanduser('~/.anwbis'), 'w+') as json_file:
                #json_file.seek(0)
                #root_json_data = json.load(json_file)
                #print "se ha leido... "
                #print json.dumps(root_json_data)
                if project_name not in root_json_data:
                    json_data = root_json_data[project_name] = {}
                if environment_name not in root_json_data[project_name]:
                    json_data = root_json_data[project_name][environment_name] = {}
                if role_name not in root_json_data[project_name][environment_name]:
                    json_data = root_json_data[project_name][environment_name][role_name] = {}
                json_data = root_json_data[project_name][environment_name][role_name]["anwbis_last_timestamp"] = str(int(time.time()))
                json_data = root_json_data[project_name][environment_name][role_name]["access_key"] = access_key
                json_data = root_json_data[project_name][environment_name][role_name]["role_session_name"] = role_session_name
                json_data = root_json_data[project_name][environment_name][role_name]["session_key"] = session_key
                json_data = root_json_data[project_name][environment_name][role_name]["session_token"] = session_token
                #print "cerrando..."
                json.dump(root_json_data, json_file)
    else:
        with open(os.path.expanduser('~/.anwbis'), 'w+') as json_file:
            data = { project_name: { environment_name: { role_name: {"anwbis_last_timestamp": str(int(time.time())),
            "access_key": access_key,
            "role_session_name": role_session_name,
            "session_key": session_key,
            "session_token": session_token } } } }
            json.dump(data, json_file)

def get_sts_token(sts_connection, role_arn, mfa_token, mfa_serial_number, role_session_name, project_name, environment_name, role_name):
    try:
        assumed_role_object = sts_connection.assume_role(
            role_arn=role_arn,
            role_session_name=role_session_name,
            duration_seconds=3600,
            mfa_serial_number=mfa_serial_number,
            mfa_token=mfa_token
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

    save_credentials(access_key, session_key, session_token, role_session_name, project_name, environment_name, role_name)

    return { 'access_key':access_key, 'session_key': session_key, 'session_token': session_token, 'role_session_name': role_session_name }


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
    def token(self):
        global region
        global role
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

        if args.role:
            role = args.role
        else:
            role = 'developer'

        if args.profile:
            profile_name = args.profile

        if args.region:
            region = args.region
        else:
            region = 'eu-west-1'

        project = args.project
        project = project.lower()
        verbose("Proyect: "+project)

        env = args.env
        env = env.lower()
        verbose("Environment: "+env)

        if args.browser:
            browser = args.browser
        else:
            browser = 'none'

        # Get Corp Account ID and set session name

        if args.profile:
            iam_connection = IAMConnection(profile_name=args.profile)
        else:
            iam_connection = IAMConnection()

        #role_session_name=iam_connection.get_user()['get_user_response']['get_user_result']['user']['user_name']
        try:
            role_session_name=iam_connection.get_user().get_user_response.get_user_result.user.user_name
        except Exception, e:
            colormsg ("There was an error retrieving your session_name. Check your credentials", "error")
            verbose(e)
            exit(1)

        #account_id=iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]
        try:
            account_id=iam_connection.get_user().get_user_response.get_user_result.user.arn.split(':')[4]
        except Exception, e:
            colormsg ("There was an error retrieving your account id. Check your credentials", "error")
            verbose(e)
            exit(1)

        # Regexp for groups and policies. Set the policy name used by your organization

        group_name='corp-'+project+'-master-'+role
        policy_name='Delegated_Roles'
        role_filter = env+'-'+project+'-delegated-'+role

        # Step 1: Prompt user for target account ID and name of role to assume

        # IAM groups
        verbose("Getting IAM group info:")
        delegated_policy = []
        group_policy = []
        delegated_arn = []

        try:
            policy = iam_connection.get_group_policy( group_name, policy_name)
        except Exception, e:
            colormsg ("There was an error retrieving your group policy. Check your credentials, group_name and policy_name", "error")
            verbose(e)
            exit(1)
        policy = policy.get_group_policy_response.get_group_policy_result.policy_document
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
            colormsg ("Sorry, you are not authorized to use the role "+role+" for project "+project, "error")
            exit(1)

        elif len(delegated_arn) == 1:
            account_id_from_user = delegated_arn[0].split(':')[4]
            role_name_from_user = delegated_arn[0].split('/')[1]

        else:
            colormsg("There are two or more policies matching your input", "error")
            exit(1)

        colormsg("You are authenticated as " + role_session_name, "ok")

        #MFA
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
        verbose("Assuming role "+ role_arn+ " using MFA device " + mfa_serial_number + "...")
        colormsg("Assuming role "+ role+ " from project "+ project+ " using MFA device from user "+ role_session_name+ "...", "normal")

        json_data = None
        json_file = None

        if os.path.isfile(os.path.expanduser('~/.anwbis')):
            #print "existe"
            with open(os.path.expanduser('~/.anwbis')) as json_file:
                root_json_data = json.load(json_file)
                json_file.close()

                if project in root_json_data and env in root_json_data[project] and role in root_json_data[project][env]:
                    json_data = root_json_data[project][env][role]
                    anwbis_last_timestamp = json_data["anwbis_last_timestamp"]

                    #check if the token has expired
                    if int(time.time()) - int(anwbis_last_timestamp) > 3600 :
                        #print "token has expired"
                        mfa_token = raw_input("Enter the MFA code: ")
                        sts_token = get_sts_token(sts_connection, role_arn, mfa_token, mfa_serial_number, role_session_name, project, env, role)

                    else:
                        #print "token has not expired, trying to login..."
                        login_to_fedaccount(json_data["access_key"], json_data["session_key"], json_data["session_token"], json_data["role_session_name"])
                        sts_token = {'access_key':json_data["access_key"], 'session_key':json_data["session_key"], 'session_token': json_data["session_token"], 'role_session_name': json_data["role_session_name"]}

                else:

                    mfa_token = raw_input("Enter the MFA code: ")
                    sts_token = get_sts_token(sts_connection, role_arn, mfa_token, mfa_serial_number, role_session_name, project, env, role)

        else:
            #print ".anwbis configuration file doesnt exists"
            # Prompt for MFA one-time-password and assume role
            print "role is " +  role
            mfa_token = raw_input("Enter the MFA code: ")
            sts_token = get_sts_token(sts_connection, role_arn, mfa_token, mfa_serial_number, role_session_name, project, env, role)

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
    def main(self):
        global access_key
        global session_key
        global session_token
        token = self.token()
        access_key = token['access_key']
        session_key = token['session_key']
        session_token = token['session_token']
        self.controller()
#This idiom means the below code only runs when executed from command line

if __name__ == '__main__':
    a = Anwbis()
    a.main()

