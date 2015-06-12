
# ANWBIS - Amazon Account Access
==================================================

## Introduction

Anwbis is a CLI tool to create temporary credentials to log into a AWS delegated account. For this you must have a central account where you add all your users (corp account) with the only permissions to assume roles cross-accounts, then the user must be added to the group that you want to let access the delegated account. 


## Installation

simply generate the egg and install it with the setup.py program, to do this be sure you have **python 2.X** installed (python3 is unsupported), so you might need to use **python, python2, or python2.6, o python2.7** as interpreter, in the following example I used **python2**.

'''
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
'''

## Running the CLI

now you can simply type the anwbis command anywhere in your system, you must provide always the project name (-p), the environment (-e) and the role (-r). If you want to that Awnbis opens a web tab in your browser with the console of that particular account just add -b and either chrome/google-chrome/firefox depending on your favorite browser installation, i.e

'''
[luix@boxita ~]$ anwbis -p datalab -e dev -r admin -b firefox

AnWbiS Amazon Account Access 1.2.0

iam:grouppolicy, corp-datalab-master-admin, Delegated_Roles, 3c78b4798a75ad40f75405356a139a7.....

[ OK ] You are authenticated as luis.gonzalez


Assuming role admin from project datalab using MFA device from user luis.gonzalez...

role is admin
Enter the MFA code: 471265

[ OK ] Assumed the role successfully

'''
