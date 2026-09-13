@echo off
REM Run the Scyther CLI against the UWC protocol model.
REM Requires Scyther to be installed and scyther-cli.exe to be on PATH.

scyther-cli uwc_protocol.spdl
pause
