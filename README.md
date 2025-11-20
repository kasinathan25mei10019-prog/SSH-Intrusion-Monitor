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
