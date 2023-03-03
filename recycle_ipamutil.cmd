@ECHO OFF

ECHO Stopping IPAMUtil
nssm stop IPAMUtil

ECHO Waiting 10 secs
PING localhost -n 10 >NUL

ECHO Starting IPAMUtil
nssm start IPAMUtil

ECHO Waiting 10 secs
PING localhost -n 10 >NUL
