# SSH-Intrusion-Monitor

Overview of the Project

Following is a Python script for real-time log analysis, a simple program to monitor Linux SSH authentication logs. It instantly detects login attempts, especially those associated with brute-force attacks.

It does a similar job to the tail -f command but adds critical security intelligence by breaking down unstructured log lines, classifying events as SUCCESS/FAILURE, and providing instant, alerts. This reduces detection latency significantly compared to manual log review.

Features

  Real-Time Tailing: It continuously monitors the log file and processes new lines as they are appended.

  Structured Breakdown using: Uses a robust pattern for Regular Expression to extract reliably key data points:

  1.Timestamp

  2.Source IP Address

  3.Target Username

Event Classification: This automatically identifies whether an event was a successful login-usually referred to as SUCCESS-or a failed attempt, usually referred to as FAILURE.

Modular design: This code is divided into small functions, each responsible for a module of the software - line_re, activity, and monitoring - which makes the code logic very clear and easy to extend.

Tools Used

  This script uses libraries like time and re

  the re library is used to extract the data from each lines in the log file

  the time library is used to estimate the current time so that the user can identify when users are trying to login or has successfully logged in

Steps to install & run the project

  This script only uses two libraries that is mostly built in, if the libraries are not found you can install them using

  pip install regex for getting the re library 

  pip install time for getting the time library

  Usually it is pre installed and does not need any action

Instructions for testing

  The script is designed to read the log file of linux based operating systems such as ubuntu,etc

  The path of the file must be acurately specified, otherwise error will appear

  The test.log file is a sample log file that can be used for testing the script, while appending new lines in test.log ensure you use echo(in ubuntu, as this scrpit is based on linux ) command to add new lines in test.log
