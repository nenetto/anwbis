#!/usr/bin/env python
import requests # "pip install requests"
import sys, os, urllib, json, webbrowser
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
print "		   	Amazon Account Access	 "                                          
                                          

 

# Step 1: Prompt user for target account ID and name of role to assume
if len(sys.argv) == 3:
    account_id_from_user = sys.argv[1]
    role_name_from_user = sys.argv[2]
    browser = 'default'
elif len(sys.argv) >= 4:
    account_id_from_user = sys.argv[1]
    role_name_from_user = sys.argv[2]
    browser = sys.argv[3]
else:
    print "\n\tUsage: ",
    print os.path.basename(sys.argv[0]), # script name
    print " <account_id> <role_name> <browser>"
    print ""
    print "(browser is an optional parameter. Valid values: firefox | chrome | none (link to login) | default"
    print ""
    exit(0)
 
# Create an ARN out of the information provided by the user.
role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
role_arn += role_name_from_user

iam_connection = IAMConnection()

#role_session_name="AssumedRole"
role_session_name=iam_connection.get_user()['get_user_response']['get_user_result']['user']['user_name']
print ""
print "You are authenticated as " + role_session_name
print ""
mfa_serial_number = "arn:aws:iam::406362555173:mfa/"+role_session_name


 
# Step 2: Connect to AWS STS and then call AssumeRole. This returns 
# temporary security credentials.
sts_connection = STSConnection()
#MFA
# Assume the role
print "\nAssuming role", role_arn, "using MFA device", mfa_serial_number, "..."
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

# Easter Egg: Say Goodbye

if len(sys.argv) == 5 and sys.argv[4] == 'goodbye':
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