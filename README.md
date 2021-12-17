# l4jScan

Log4j Detection and IOC scanner written in Bash

This script will use various methods to detect if a Linux host has Log4j installed and if so, it will scan for exploitation attempts in web logs.

As always this script is not 100% proof that a host is not vulnerable to the exploit but will hopefully help identify hosts of interest across a large estate.

Remember to buy your nearest incident responder a beer <3

Usage:
Just run without arguments as a root user or user with sudo access (for log file & updatedb permissions)
