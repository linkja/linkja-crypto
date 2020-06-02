del CMakeCache.txt
del src\linkjacrypto.exp
del src\linkjacrypto.lib
del src\linkjacrypto.dll
del src\linkjacrypto.dll.manifest

REM del src\include\linkja_secret.h

PATH=%PATH%;C:\Development\OpenSSL\vc-win64a\bin

cmake -DCMAKE_BUILD_TYPE=Release -G "NMake Makefiles" .
nmake clean
nmake