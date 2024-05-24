
let rooms: any[] = [];
let backendUri = `${process.env.BACKEND_HOST || 'grandresort.challs.open.ecsc2024.it'}:${process.env.BACKEND_PORT || '3001'}`;

export const load = (async () => {
    const grpc = await import('@grpc/grpc-js');
    const protoLoader = await import('@grpc/proto-loader');
    const pd = protoLoader.loadSync("grand-resort.proto");
    const descriptor = grpc.loadPackageDefinition(pd);
    let stub = new descriptor.GrandResort.Reception(backendUri, grpc.credentials.createInsecure());
    stub.listRooms({}, (e: any,f: object) => {
      rooms = f.rooms;
    })

    return {
      rooms
    };
  }
);