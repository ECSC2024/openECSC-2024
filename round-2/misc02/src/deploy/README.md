# Deployment of challenge

- [Exposed endpoints](#exposed-endpoints)
- [Server requirements](#server-requirements)
- [Hardware requirements](#hardware-requirements)
- [Configuration](#configuration)
  - [Web Server](#web-server)
  - [Captcha](#captcha)
  - [Workers](#workers)
- [Deployment](#deployment)
  - [Windows features](#windows-features)
  - [Base setup](#base-setup)
  - [Docker setup](#docker-setup)
  - [Queue/Runner setup](#queuerunner-setup)
- [Configuration changes](#configuration-changes)
  - [Flag](#flag)
  - [Queue/Runner configuration](#queuerunner-configuration)
- [Troubleshooting](#troubleshooting)

## Exposed endpoints

A web server is exposed on `http://0.0.0.0:5000`. It is recommended to use a reverse proxy to expose the web server to the internet.

## Server requirements

This challenge is deployed on a Windows Server 2022 machine. The deployment is done using Docker and a queue/runner setup.

The challenge must be setup on a Windows Server with version "10.0.20348.0", as the Docker container image relies on having the same kernel version as the host. Alternatively, change the base image in the Dockerfile to match the host version.

You can check the Windows version using the following PowerShell command:

```powershell
[Environment]::OSVersion.Version.ToString()
```

## Hardware requirements

- Minimum of (2GB RAM for Windows Server Desktop Experience or 512MB RAM for Windows Server Core) + 150MB per worker
- Minimum 20GB disk space
- Minimum 2 CPU cores

## Configuration

### Web Server

By default, the web server listens on all interfaces on port 5000. If you need to change the binding interface or port, you can do so by changing the `Url` value in the [./build/Hosting/WebServer/Release/appsettings.json](./build/Hosting/WebServer/Release/appsettings.json) file.

```json
{
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:5000"
      }
    }
  }
}
```

### Captcha

The challenge requires reCAPTCHA v2 keys to be in [./config.json](./config.json) file.

```json
{
    "CaptchaKey": "<private key>"
}
```

Remember to change the [./build/Hosting/WebServer/Release/wwwroot/index.html](./build/Hosting/WebServer/Release/wwwroot/index.html) file to include your reCAPTCHA v2 public key.

```html
<div class="g-recaptcha" data-sitekey="<public key>"></div>
```

### Workers

It is possible to change the number of simultaneous workers by changing the `Workers` value in the [./config.json](./config.json) file.

```json
{
  "QueueSettings": {
    "Workers": 10
  }
}
```

## Deployment

Copy the current folder to the Windows Server and follow the steps below. Feel free to exclude the [./build/Solution/](./build/Solution/) folder from the [./build/](./build/) directory if you do not need to check the solution on the same machine.

Run all commands in an administrative PowerShell with the current directory set to this copied folder.

### Windows features

The Windows Server must have the following Windows features installed:

- Containers
- MSMQ

The following PowerShell command can be used to install the features:

```powershell
Install-WindowsFeature -Name Containers,MSMQ -Restart
```

### Base setup

1. Create the base folder and copy `config.json` to the folder.

```powershell
New-Item -Path "C:\RemoteDiagnostics" -ItemType "directory"
Copy-Item -Path "config.json" -Destination "C:\RemoteDiagnostics\config.json" -Force
```

2. Copy the build files to the base folder.

```powershell
Copy-Item -Path .\build\ -Destination C:\RemoteDiagnostics\build -Recurse
```

3. Write the flag file to the base folder.

```powershell
Write-Output "flag{test}" | Out-File "C:\RemoteDiagnostics\flag.txt" -Encoding ascii -NoNewline
```

### Docker setup

1. Setup and install Docker on the Windows Server.

```powershell
Invoke-WebRequest -Uri https://master.dockerproject.com/windows/x86_64/docker.zip -OutFile docker.zip

Expand-Archive -Path docker.zip -DestinationPath C:\RemoteDiagnostics\ -Force

net.exe localgroup docker /add
net.exe localgroup docker $env:username /add

sc.exe create docker binPath= '"C:\RemoteDiagnostics\docker\dockerd.exe" -H npipe:////./pipe/docker -G docker --exec-opt isolation=process --run-service' start= auto

sc.exe start docker
sc.exe query docker
```

2. Wait for the `sc.exe query docker` command to show the status as `RUNNING`.

3. Build the Docker image.

```powershell
Copy-Item -Path "C:\RemoteDiagnostics\build\Handout\RemoteDiagnostics.Client.exe" -Destination "Docker\RemoteDiagnostics.Client.exe" -Force
Copy-Item -Path "C:\RemoteDiagnostics\build\Handout\RemoteDiagnostics.Contract.dll" -Destination "Docker\RemoteDiagnostics.Contract.dll" -Force

C:\RemoteDiagnostics\docker\docker.exe -H npipe:////./pipe/docker build -t diagnostics:latest Docker
```

### Queue/Runner setup

1. Install Dotnet 7.0 ASP.NET Core Runtime. (https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script)

```powershell
.\dotnet-install.ps1 -Channel 7.0 -Runtime aspnetcore -InstallDir "C:\Program Files\dotnet\"
```

2. Create and run the queue services.

```powershell
sc.exe create "Diagnostics Queue Worker Service" binpath="C:\RemoteDiagnostics\build\Hosting\Worker\Release\QueueRunner.Worker.exe" start= auto depend= MSMQ
sc.exe create "Diagnostics Queue Web Server Service" binpath="C:\RemoteDiagnostics\build\Hosting\WebServer\Release\QueueRunner.WebServer.exe" start= auto depend= MSMQ

sc.exe start "Diagnostics Queue Worker Service"
sc.exe start "Diagnostics Queue Web Server Service"

sc.exe query "Diagnostics Queue Worker Service"
sc.exe query "Diagnostics Queue Web Server Service"
```

3. Wait for the `sc.exe query` commands to show the status as `RUNNING`.

## Configuration changes

### Flag

The flag is located at `C:\RemoteDiagnostics\flag.txt`. If you need to change the flag, you can do so without restarting the services.
  
```powershell
Write-Output "flag{test}" | Out-File "C:\RemoteDiagnostics\flag.txt" -Encoding ascii -NoNewline
```

### Queue/Runner configuration

If you need to change the `C:\RemoteDiagnostics\config.json` or `C:\RemoteDiagnostics\build\Hosting\WebServer\Release\appsettings.json` configuration, you can stop the services, make the changes, and start the services again.

```powershell
sc.exe stop "Diagnostics Queue Worker Service"
sc.exe stop "Diagnostics Queue Web Server Service"

# Make changes to the configuration

sc.exe start "Diagnostics Queue Worker Service"
sc.exe start "Diagnostics Queue Web Server Service"
```

## Troubleshooting

If you encounter any issues, check the Windows Event Viewer for logs. The logs can be found under `Windows Logs` -> `Application`. Look for `docker`, `Diagnostics Queue Worker Service` and `Diagnostics Queue Web Server Service` logs.

If you encounter issues related to MSMQ and queues, the most likely cause is that the binaries were run using a different user, which results in the queues not being accessible by other users, such as the services. To fix this, you can change the queue name in the `config.json` file and restart the services.

```json
{
  "QueueSettings": {
    "QueueName": "DiagnosticsRunnerQueue"
  }
}
```