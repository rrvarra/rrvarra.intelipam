@ECHO OFF

ECHO Stopping INTELIPAM_WEBAPP
sc stop INTELIPAM_WEBAPP

ECHO Waiting 10 secs
PING localhost -n 10 >NUL

ECHO Starting INTELIPAM_WEBAPP
sc start INTELIPAM_WEBAPP

ECHO Waiting 10 secs
PING localhost -n 10 >NUL

sc queryex INTELIPAM_WEBAPP

