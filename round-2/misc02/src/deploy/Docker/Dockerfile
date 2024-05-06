FROM mcr.microsoft.com/windows/servercore:ltsc2022

COPY RemoteDiagnostics.Client.exe C:/
COPY RemoteDiagnostics.Contract.dll C:/

USER ContainerUser

ENTRYPOINT ["C:/RemoteDiagnostics.Client.exe"]