#!/usr/bin/env python
import argparse
import requests # "pip install requests"
import sys, os, urllib, json, webbrowser
import hashlib
import re
from boto.sts import STSConnection # AWS Python SDK--"pip install boto"
from boto.iam import IAMConnection 


print ""
print "             __          ___     _  _____ "
print "     /\      \ \        / / |   (_)/ ____|"
print "    /  \   _ _\ \  /\  / /| |__  _| (___  "
print "   / /\ \ | '_ \ \/  \/ / | '_ \| |\___ \ "
print "  / ____ \| | | \  /\  /  | |_) | |____) |"
print " /_/    \_\_| |_|\/  \/   |_.__/|_|_____/ "
print ""
print "	   	Amazon Account Access 	v1.1.0       "                                          
                                          

 
# Step 1: Parse CLI
global VERBOSE

parser = argparse.ArgumentParser(description='AnWbiS: AWS Account Access')
parser.add_argument('--version', action='version', version='%(prog)s 1.0.3')
parser.add_argument('--project', '-p', required=True, action = 'store', help = 'project to connect', default=False)
parser.add_argument('--env', '-e', required=True, action = 'store', help = 'Set environment (dev | pre | pro | val | corp)', default=False)
parser.add_argument('--role', '-r', required=False, action = 'store', help = 'Set role to use (developer | admin | default: developer)', default=False)
parser.add_argument('--browser', '-b', required=False, action = 'store', help = 'Set browser to use (firefox | chrome | default | none)', default=False)
parser.add_argument('--goodbye', '-g', required=False, action='store_true', help = 'There is no easter eggs in this code, but AnWbiS can say goodbye', default=False)


parser.add_argument('--verbose', '-v', 
               action = 'store_true',
               help = 'prints verbosely',
               default=False)

args = parser.parse_args()

def verbose(str):
    if args.verbose:
        print str

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

def filterbyvalue(seq, value):
   for el in seq:
       print el.attribute
       if el.attribute==value: yield el


if args.verbose:
    VERBOSE=True

if args.role:
    role = args.role
else:
    role = 'developer'

if args.browser:
    browser = args.browser
else:
    browser = 'none'

project = args.project
print "proyecto "+project
env= args.env
print "entorno "+env    

# Get Corp Account ID and set session name

iam_connection = IAMConnection()

role_session_name=iam_connection.get_user()['get_user_response']['get_user_result']['user']['user_name']
account_id=iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]


# Regexp for groups and policies

group_name='corp-'+project+'-master-'+role
policy_name='Delegated_Roles'
role_filter = env+'-'+project+'-delegated-'+role

# Step 1: Prompt user for target account ID and name of role to assume
#if len(sys.argv) == 3:
#    account_id_from_user = sys.argv[1]
#    role_name_from_user = sys.argv[2]
#    browser = 'default'
#elif len(sys.argv) >= 4:
#    account_id_from_user = sys.argv[1]
#    role_name_from_user = sys.argv[2]
#    browser = sys.argv[3]
#else:
#    print "\n\tUsage: ",
#    print os.path.basename(sys.argv[0]), # script name
#    print " <account_id> <role_name> <browser>"
#    print ""
#    print "browser is an optional parameter. Valid values: firefox | chrome | none (link to login) | default"
#    print ""
#    exit(0)
 

# IAM groups
verbose("Getting IAM group info:")
delegated_policy = []
#groups_delegated = iam_connection.get_group_policy()( 'corp-'+project+'-master-'+role, 'Delegated_Roles' )['get_group_policy_response']['get_group_policy_result']['policy_document']
#for group in groups_delegated:
#    verbose("Group " + group.group_name)
# Policies attached to groups
#policies_delegated = iam_connection.get_group_policy( 'corp-'+project+'-master-'+role, 'Delegated_Roles' )
#policies_delegated = policies_delegated.list_group_policies_response.list_group_policies_result.policy_names

group_policy = []

policy = iam_connection.get_group_policy( group_name, policy_name)
policy = policy.get_group_policy_response.get_group_policy_result.policy_document
policy = urllib.unquote(policy)
group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

output_lines(group_policy)

#format policy


policy = re.split('"', policy)

delegated_arn = []


for i in policy:
    result_filter = re.search (role_filter, i)
    if result_filter:
        delegated_arn.append(i) 

if len(delegated_arn) == 0:
    print ""
    print "ERROR"
    print "Sorry, you are not authorized to use the role "+role+" for project "+project 
    exit(1)

elif len(delegated_arn) == 1:
    account_id_from_user = delegated_arn[0].split(':')[4]
    role_name_from_user = role_filter

else:
    print ""
    print "ERROR"
    print "There are two or more policies matching your input"
    exit(1)

print ""
print "You are authenticated as " + role_session_name
print ""
mfa_serial_number = "arn:aws:iam::"+account_id+":mfa/"+role_session_name

# Create an ARN out of the information provided by the user.
role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
role_arn += role_name_from_user

 
# Step 2: Connect to AWS STS and then call AssumeRole. This returns 
# temporary security credentials.
sts_connection = STSConnection()
#MFA

# Assume the role
verbose("\nAssuming role "+ role_arn+ " using MFA device " + mfa_serial_number + "...")

print "\nAssuming role", role, "from project", project, "using MFA device from user", role_session_name, "..."


# Prompt for MFA one-time-password
mfa_token = raw_input("Enter the MFA code: ")
assumed_role_object = sts_connection.assume_role(
    role_arn=role_arn,
    role_session_name=role_session_name,
    mfa_serial_number=mfa_serial_number,
    mfa_token=mfa_token
)
print ""
print "Assumed the role successfully."
print ""
 
# Step 3: Format resulting temporary credentials into a JSON block using 
# known field names.

access_key = assumed_role_object.credentials.access_key
session_key = assumed_role_object.credentials.secret_key
session_token = assumed_role_object.credentials.session_token
json_temp_credentials = '{'
json_temp_credentials += '"sessionId":"' + access_key + '",'
json_temp_credentials += '"sessionKey":"' + session_key + '",'
json_temp_credentials += '"sessionToken":"' + session_token + '"'
json_temp_credentials += '}'
 
# Step 4. Make a request to the AWS federation endpoint to get a sign-in 
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
 
# Step 5. Get the return value from the federation endpoint--a 
# JSON document that has a single element named 'SigninToken'.
sign_in_token = json.loads(r.text)["SigninToken"]
 
# Step 6: Create the URL that will let users sign in to the console using 
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

#if len(sys.argv) == 5 and sys.argv[4] == 'goodbye':
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
    print " Thank you for using AnWBiS. Goodbye!"
    print ""
 
# Step 7: Use the default browser to sign in to the console using the
# generated URL.
chrome_path = '/usr/bin/google-chrome %s'
firefox_path = '/usr/bin/firefox %s'
if browser == 'firefox':
    webbrowser.get(firefox_path).open(request_url)
elif browser == 'chrome': 
    webbrowser.get(chrome_path).open(request_url)
elif browser == 'default':
    webbrowser.open(request_url)
elif browser == 'none':
    print request_url
else: 
    webbrowser.open(request_url)
