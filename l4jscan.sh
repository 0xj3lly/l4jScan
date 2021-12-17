#!/bin/bash

cat << "EOF"
  _   _  _   _  _____                 
 | | | || | (_)/ ____|                
 | | | || |_ _| (___   ___ __ _ _ __  
 | | |__   _| |\___ \ / __/ _` | '_ \ 
 | |____| | | |____) | (_| (_| | | | |
 |______|_| | |_____/ \___\__,_|_| |_|
           _/ |   by 0xj3lly                    
          |__/                                                            
EOF

echo "Checks for IOCs if Log4j or Java is installed"
echo "This should be run as root or as a user with sudo access"

RED="\033[0;31m"; GREEN="\033[32m"; YELLOW="\033[1;33m"; ENDCOLOR="\033[0m"
WARNING="[WARNING]"${ENDCOLOR}

HOSTOFINTEREST=0

if [ "$(command -v updatedb)" ]; then
  echo -e ${YELLOW}"# find files containing log4j with locate"${ENDCOLOR}
  sudo updatedb
  OUTPUT="$(locate -e log4j|grep -v log4js)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" log4j files detected, check files for potentially vulnerable versions"
    echo "$OUTPUT"
    HOSTOFINTEREST=1
  else
  echo -e ${GREEN}"[OK]"${ENDCOLOR}"  No Log4j files discovered via locate"
  fi;
else
  echo -e ${YELLOW}"# search files containing log4j with find"${ENDCOLOR}
  OUTPUT="$(find \
      /var /etc /usr /opt /lib* \
      -name "*log4j*" \
      2>&1 \
      | grep -v '^find:.* Permission denied$' \
      | grep -v '^find:.* No such file or directory$')"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" Found potential log4j files"
    echo "$OUTPUT"
    HOSTOFINTEREST=1
  else
    echo -e ${GREEN}"[OK]"${ENDCOLOR}"  No Log4j files discovered via find"
  fi;
fi;
if [ "$(command -v rpm)" ]; then
  echo -e ${YELLOW}"# check yum packages"${ENDCOLOR}
  OUTPUT="$(rpm -qa *log4j* |grep -v log4js)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" Potentially vulnerable, yum installed packages:"
    echo "$OUTPUT"
    HOSTOFINTEREST=1
  else
  echo -e ${GREEN}"[OK]"${ENDCOLOR}"  No Log4j packages discovered in yum"
  fi;
fi;
if [ "$(command -v dpkg)" ]; then
  echo -e ${YELLOW}"# check dpkg packages"${ENDCOLOR}
  OUTPUT="$(dpkg -l|grep log4j|grep -v log4js)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" Potentially vulnerable, dpkg installed packages:"
    echo "$OUTPUT"
    HOSTOFINTEREST=1
  else
  echo -e ${GREEN}"[OK]"${ENDCOLOR}" No Log4j packages discovered in dpkg"
  fi;
fi;
echo -e ${YELLOW}"# check if Java is installed"${ENDCOLOR}
JAVA="$(command -v java)"
if [ "$JAVA" ]; then
  echo -e ${RED}"[WARNING]"${ENDCOLOR}" Java is installed"
  echo "Java applications often bundle their libraries inside jar/war/ear files, so there still could be log4j in such applications.";
  HOSTOFINTEREST=1
else
  echo -e ${GREEN}"[OK]"${ENDCOLOR}" Java is not installed"
fi;
echo -e ${YELLOW}"_________________________________________________"${ENDCOLOR}
if [ "$JAVA" == "" ]; then
  echo "Some apps bundle the vulnerable library in their own compiled package, so 'java' might not be installed but one such apps could still be vulnerable."
fi;
echo

if [ "$HOSTOFINTEREST" = 1 ]; then
  echo -e ${YELLOW}"# Host is potentially vulnerable. Scanning logs for exploitation attempts"${ENDCOLOR}
  EXPLOITATTEMPT=0
  OUTPUT="$(sudo egrep -I -i -r '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+' /var/log)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" potentially vulnerable and exploitation attempt found"
    echo "$OUTPUT"
    EXPLOITATTEMPT=1
  fi;
  OUTPUT="$(sudo find /var/log -name \*.gz -print0 | xargs -0 zgrep -E -i '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+')"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" potentially vulnerable and exploitation attempt found"
    echo "$OUTPUT"
    EXPLOITATTEMPT=1
  fi;
  OUTPUT="$(sudo find /var/log/ -type f -exec sh -c "cat {} | sudo sed -e 's/\${lower://'g | tr -d '}' | sudo egrep -I -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" potentially vulnerable and exploitation attempt found"
    echo "$OUTPUT"
    EXPLOITATTEMPT=1
  fi;
  OUTPUT="$(sudo find /var/log/ -name '*.gz' -type f -exec sh -c "zcat {} | sudo sed -e 's/\${lower://'g | tr -d '}' | sudo egrep -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;)"
  if [ "$OUTPUT" ]; then
    echo -e ${RED}"[WARNING]"${ENDCOLOR}" potentially vulnerable and exploitation attempt found"
    echo "$OUTPUT"
    EXPLOITATTEMPT=1
  fi;
  if [ "$EXPLOITATTEMPT" = 0 ]; then
    echo -e ${YELLOW}"[WARNING]"${ENDCOLOR}" potentially vulnerable but no exploitation attempt found"
  fi;
fi;
