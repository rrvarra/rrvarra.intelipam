@ECHO OFF

REM Create the INTELIPAM_WEBAPP Flask App as a service
SET NSSM=nssm.exe
SET SERVICE=INTELIPAM_WEBAPP
SET ROOT_DIR=D:\INTELIPAM
SET RUN_CMD=%ROOT_DIR%\run_intelipam_webapp.cmd
SET LOG_DIR="D:\LOGS\INTELIPAM"

IF NOT EXIST "%ROOT_DIR%" (
    ECHO %SERVICE% installation dir %ROOT_DIR% not found
    GOTO eof
)

IF NOT EXIST "%LOG_DIR%" (
    mkdir %LOG_DIR%
)


%NSSM% install %SERVICE% "%RUN_CMD%"
%NSSM% set %SERVICE% AppDirectory "%ROOT_DIR%"
%NSSM% set %SERVICE% Description "%SERVICE% NSSM Service"
%NSSM% set %SERVICE% AppStdout "%LOG_DIR%\%SERVICE%_ServiceStdout.log"
%NSSM% set %SERVICE% AppStderr "%LOG_DIR%\%SERVICE%_ServiceStderr.log"
%NSSM% set %SERVICE% Start SERVICE_DELAYED_AUTO_START
%NSSM% set %SERVICE% AppEnvironmentExtra SYNERGYSKY_LOADER_USER="SYNERGYSKY_LOADER" SYNERGYSKY_LOADER_PASSWORD="SETITPLEASE"


ECHO %SERVICE% Service created successfully.

:eof
