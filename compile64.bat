@ECHO OFF

cl.exe /nologo /MT /Od /GS- /DNDEBUG /W0 /Tp Src\\main.cpp /link /OUT:Bin\\DetectCobaltStomp.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
del *.obj