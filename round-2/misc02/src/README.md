# Remote Diagnostics

- [Overview](#overview)
- [Building the source](#building-the-source)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
- [Deploying the solution](#deploying-the-solution)

## Overview

This challenge consists of a client-server application. The goal for the participant is to host a malicious server that listens for incoming connections and exploits the challenge client. A web interface is provided to the participant to submit their server's IP address and port. The challenge client will connect to the participant's server and perform a series of actions. These actions are hardcoded in the client, and the participant can therefore examine the client to understand what the client will do. Refer to [../writeup.md](../writeup.md) for a detailed writeup of the challenge, and to [../attachments/README.md](../attachments/README.md) for the extended instructions provided to the participants.

The challenge is deployed on a Windows Server 2022 machine. The deployment is done using Docker and a queue/runner setup using MSMQ. The queue/runner setup consists of a web server and a background service. Participants can submit their server's IP address and port to the web server, which are then added to a queue. The queue is consumed by a background service that spawns a fresh Docker container for each item in the queue. The Docker container runs the challenge client, which connects to the participant's server. The Docker container is then forcefully destroyed after 30 seconds. Refer to [./deploy/README.md](./deploy/README.md) for further details on the deployment, infrastructure, and configuration.

## Building the source

### Prerequisites

- Visual Studio 2022 with the following features:
  - ASP.NET and web development (.NET 7.0)
  - .NET desktop development (.NET Framework 4.7.2)
  - Desktop development with C++

Note that the solution can likely be built using different versions, but this is the version used during development.

### Building

The source code can be found in the [./RemoteDiagnostics](./RemoteDiagnostics/) directory. The whole solution can be opened and built in Visual Studio 2022 Community. A complete build can be found in the [./deploy/build/](./deploy/build/) directory.

The challenge projects are prefixed with "RemoteDiagnostics". The queue/workers are prefixed with "QueueRunner". The solution projects are prefixed with "Solution". Upon building the solution, the projects are divided into the following output directories:

- [Handout](./deploy/build/Handout/)
  - Contains the challenge executables.
- [Hosting](./deploy/build/Hosting/)
  - Contains the queue/worker executables.
- [Solution](./deploy/build/Solution/)
  - Contains the challenge solution executables.

## Deploying the solution

Please refer to the [./deploy/README.md](./deploy/README.md) file for detailed instructions on deploying the solution.

All the executables within [./deploy/build/Handout/](./deploy/build/Handout/) can be shared with the participants. These files should be identical to the files in the [../attachments/](../attachments/) directory.
