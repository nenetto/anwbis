![Logo](static/logo.png "Logo")
# Amazon Account Access

## Introduction

Anwbis is a CLI tool to create temporary credentials to log into a AWS delegated account. For this you must have a central account where you add all your users (corporate account) with the only permission to assume roles cross-accounts, then the user must be added to the group that you want to let access the delegated account. 

![Squema for auth](static/esquema.png "squema for auth")

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

## Running the CLI

you can simply type the anwbis command anywhere in your system console, you must provide always the project name (-p), the environment (-e) and the role (-r). If you want that Awnbis opens a web tab in your browser with the console of that particular account just add -b and either chrome/google-chrome/firefox/chromium depending on your favorite browser installation, i.e

```
[luix@boxita ~]$ anwbis -p datalab -e dev -r admin -b firefox

AnWbiS Amazon Account Access 1.2.0

iam:grouppolicy, corp-datalab-master-admin, Delegated_Roles, 3c78b4798a75ad40f75405356a139a7.....

[ OK ] You are authenticated as luis.gonzalez


Assuming role admin from project datalab using MFA device from user luis.gonzalez...

role is admin
Enter the MFA code: 471265

[ OK ] Assumed the role successfully

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

If you are doing tests in local (i.e. for development), use the anwbis profile in your configuration (AWSIAMProfileCredentialsProvider) to use the credentials stored in the profile.
