cd /D D:\INTELIPAM
call .venv\Scripts\activate.bat
waitress-serve --host localhost --port 8000 app:app