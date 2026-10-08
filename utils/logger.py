"""
Logger
"""

from datetime import datetime


def info(message):

    now = datetime.now().strftime("%H:%M:%S")

    print(f"[INFO {now}] {message}")


def warning(message):

    now = datetime.now().strftime("%H:%M:%S")

    print(f"[WARNING {now}] {message}")


def error(message):

    now = datetime.now().strftime("%H:%M:%S")

    print(f"[ERROR {now}] {message}")