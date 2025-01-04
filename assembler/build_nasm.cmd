nasm -f win64 .\minimal_pe.asm -o .\minimal_pe.obj
link /subsystem:console /entry:main /LARGEADDRESSAWARE minimal_pe.obj
minimal_pe.exe
echo %ERRORLEVEL%

