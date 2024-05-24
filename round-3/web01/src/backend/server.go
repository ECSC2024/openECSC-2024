package main

import (
	"os"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "grand-resort/reception/service"
)

type receptionServer struct {
	pb.UnimplementedReceptionServer
}

// Endpoints' definition are in endpoints.go, which is not provided... eheheh not so easy now, uh?

func main() {
	flag := os.Getenv("FLAG")
	err := os.WriteFile("/flag.txt", []byte(flag), 0644)
	if err != nil {
		panic(err)
	}

	lis, err := net.Listen("tcp", "0.0.0.0:38010")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterReceptionServer(grpcServer, &receptionServer{})
	reflection.Register(grpcServer)
	grpcServer.Serve(lis)
}
