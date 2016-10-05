![Logo](static/logo.png "Logo")
# Amazon Account Access

## Introduction

Anwbis is a CLI tool to create temporary credentials to log into a AWS delegated account. For this you must have a central account where you add all your users (corporate account) with the only permission to assume roles cross-accounts, then the user must be added to the group that you want to let access the delegated account. 

Based on [How to Enable Cross-Account Access to the AWS Management Console](https://blogs.aws.amazon.com/security/post/Tx70F69I9G8TYG/How-to-enable-cross-account-access-to-the-AWS-Management-Console)

![Squema for auth](static/delegated.png "squema for auth")

## Dependencies

before creating the anwbis python egg and installing it, you need to install the AWS CLI, you need to make sure you have python2.x installed on your system, this means th

```
[luix@boxita ~]$ python --version
Python 3.4.3
[luix@boxita ~]$ python2.7 --version
Python 2.7.10
[luix@boxita ~]$ python2 --version
Python 2.7.10
[luix@boxita ~]$
```

it's possible that you already have installed python, just make sure which is your primary python environment, as anwbis **IS ONLY** compatible with python 2.x, 

You need to install setuptools package, so the bootstraping can create the CLI command. Please [go here](https://pypi.python.org/pypi/setuptools) and follow the installation instructions for your system.


Then you need to install the AWS Command Line Interface (also called **boto**)

```
$ pip install awscli
```

and the requests library

```
$ pip install requests
```

## Installation

simply generate the egg and install it with the setup.py program, to do this be sure you have **python 2.X** installed (python3 is unsupported), so you might need to use **python, python2, or python2.6, o python2.7** depending on your python install, in the following example I used **python2**.

```
[luix@boxita anwbis]$ sudo python2 setup.py install
running install
running bdist_egg
running egg_info
writing requirements to anwbis.egg-info/requires.txt
writing anwbis.egg-info/PKG-INFO
writing top-level names to anwbis.egg-info/top_level.txt
....
Using /usr/lib/python2.7/site-packages/colorama-0.3.3-py2.7.egg
Finished processing dependencies for anwbis==1.2.0
[luix@boxita anwbis]$
```

### Boto Version

If you have an old versión of boto or the CLI installed on your system, you need to make sure its the cli 1.7.34 at least (currently latest) since AWS changed how the CLI and boto look for the credentials in your system, you can read more about this [here](http://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs).

```
[luix@boxita .aws]$ aws --version
aws-cli/1.7.34 Python/3.4.3 Linux/4.0.5-1-ARCH
```

## Setup Corp credentials

An easy way to setup your credentials for the main (corp) account, is to install boto and set them on the **default** profile with the following command

```
$ aws configure
AWS Access Key ID [None]: AKIAIOSFO.....
AWS Secret Access Key [None]: wJalrXUtnFE......
Default region name [None]: eu-west-1
Default output format [None]: json
```

while doing so you will require to **PAIR** a MFA device such as your mobile device with Google Authenticator, and thats it!

### Groups in the master account

```
corp-<project>-master-<role_name>
```

where role name is tipically *admin*, *developer*, *devops*, *user* or *audit*. It has only a policy named *Delegated_Roles*

### Naming in the delegated account

```
 <environment>-<project>-delegated-<role_name>
```

Please note that this role must be created as type "Role for Cross-Account Access" with subtype "Provide access between AWS accounts you own"

## Using another standard 

If you dont want to use the naming convention proposed with Anwbis you need to provide the next parameters to anwbis CLI:

```
--iam_master_group: IAM group name in the master account
--iam_policy: IAM policy name to use
--iam_delegated_role: IAM delegated role to assume
```

## Running the CLI

you can simply type the anwbis command anywhere in your system console, you must provide always the project name (-p), the environment (-e) and the role (-r). If you want that Awnbis opens a web tab in your browser with the console of that particular account just add -b and either chrome/google-chrome/firefox/chromium depending on your favorite browser installation, i.e

```
[luix@boxita ~]$ anwbis -p <project_name> -e dev -r admin -b firefox

AnWbiS Amazon Account Access 1.2.0

iam:grouppolicy, corp-datalab-master-admin, Delegated_Roles, 3c78b4798a75ad40f75405356a139a7.....

[ OK ] You are authenticated as luis.gonzalez


Assuming role admin from project datalab using MFA device from user luis.gonzalez...

role is admin
Enter the MFA code: 471265

[ OK ] Assumed the role successfully

```

If you are using a contractor policy (a third party assumed role with External-ID) parameters contractor (-c) and externalid (-ext) must be provided, in order to get rid of the [deputy problem](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)

```
anwbis --profile <profile_name> -p <project_name> -e <env> -r contractor -c <contractor_role> -ext <external_id>
```

You can use Anwbis from an EC2 instance profile with the IAM role associated with the instance. Continuous Integration/Configuration Management platforms like Jenkins or Terraform can use this feature. In order to do it you need to have a Policy in the role (named 'Delegated_Roles' or the one you are going to use with the parameter --iam_delegated_role). It is advised to use an External-ID condition in order to give some kind of security about who can assume the role.

```
anwbis  -p <project_name> -e <env> -r <role> -ext <external_id> --from_ec2_role --nomfa --refresh
```

## Using get_session_token for credentials up to 8 hours

By default, Anwbis uses the sts method assume_role to get the credentials. As cross account delegation gives a maximum of 1 hour of valid credentials you must refresh the token calling Anwbis. If you need longer credentials you can override the MFA input login with longer get_session_token credentials in your corporate account.

For using this you must give your user permission to call to STS get_session_token. This gives you a set of temporary credentials with a default value of 8 hours until being prompt for another MFA code. 

```
anwbis --profile <profile_name> -p <project_name> -e <env> -r <role> --get_session
```
This saves into your ~/.aws/credentials a temporary set of credentials under the profile name **corp-session-<profile_name>**. If you didn't use the --profile option the name is **corp-session-default**.

With this credentials you can use Anwbis without being prompt for the MFA if the token is not expired:

```
anwbis --profile <corp_session_profile> -p <project_name> -e dev -r devops --nomfa -b chrome
```

You can use it even with the AWS CLI or other SDKs or tools that uses the AWS profile. Simple use it with the project generated profile:

```
aws --profile <project-env-role> s3 ls
```

## Generating AccessKeys/SecretKeys

Everytime you run Anwbis and succesfully generate a new session token, the role PROJECT-ENV-ROLE on your boto credentials (~/.aws/credentials) will be updated/created... i.e.

```
[luix@boxita ~]$ anwbis -p datalab -e dev -r admin -b firefox

....

[luix@boxita ~]$ cat .aws/credentials
[default]
aws_access_key_id = XXXXXXX
aws_secret_access_key = XXXXXXX

[datalab-dev-admin]
aws_access_key_id = XXXXXXX
aws_secret_access_key = XXXXXXX
aws_session_token = XXXXXXX

[luix@boxita ~]$
```

This means you can use the AWS CLI with the profile flag like this

```
[luix@boxita ~]$ aws s3 ls --profile datalab-dev-admin
```
and you will be running this command against the delegated account.

Another way is to export the role to the AWS_PROFILE and/or AWS_DEFAULT_PROFILE env variables, so its used by the CLI and sdks on your computer. 

Note that in AWS credentials chain system environment variables takes precedence over .aws/credentials file, so you need to use another tty or unset environment variables in order to use anwbis again.

```
[luix@boxita ~]$ export AWS_PROFILE=datalab-dev-admin; export AWS_DEFAULT_PROFILE=datalab-dev-admin
```

If you are doing tests or development in local, use the anwbis profile in your configuration with the AWS SDK credentials provider class, for instance in java __AWSIAMProfileCredentialsProvider__ will use the credentials stored in the profile nane you specify.
