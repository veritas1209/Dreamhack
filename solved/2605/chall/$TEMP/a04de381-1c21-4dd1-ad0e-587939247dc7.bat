powershell -C wget "https://www.python.org/ftp/python/3.13.5/python-3.13.5-embed-amd64.zip" -OutFile "%TEMP%\c0927431-5b2f-4dd7-b15c-7fa040f28b4a.zip"
md %TEMP%\d46f777d-6598-448a-b112-7dab55299260
tar -xf "%TEMP%\c0927431-5b2f-4dd7-b15c-7fa040f28b4a.zip" -C "%TEMP%\d46f777d-6598-448a-b112-7dab55299260"
cd %TEMP%\d46f777d-6598-448a-b112-7dab55299260
powershell -C wget "https://bootstrap.pypa.io/get-pip.py" -OutFile "f2d99fce-e48d-41e3-93a1-36e3d6195e1c.py"
python f2d99fce-e48d-41e3-93a1-36e3d6195e1c.py
echo import site>>python313._pth
Scripts\pip install pycryptodome