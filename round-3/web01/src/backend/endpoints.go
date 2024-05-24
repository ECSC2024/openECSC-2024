package main

import (
	"context"
	"github.com/lithammer/dedent"
	"google.golang.org/protobuf/types/known/emptypb"
	pb "grand-resort/reception/service"
	"strings"
)

func (s *receptionServer) CreateRoomRequestModelc21A7F50(ctx context.Context, empty *emptypb.Empty) (*pb.RoomRequestModel, error) {
	return &pb.RoomRequestModel{
		RoomRequestModel: strings.TrimSpace(dedent.Dedent(`
    <?xml version="1.0" encoding="UTF-8"?>
    <room>
        <name>RoomName</name>
        <price>$100.0</price>
        <description>RoomDescription</description>
        <size>30 m2</size>
    </room>
    `)),
	}, nil
}

func (s *receptionServer) CreateRoom73950029(ctx context.Context, roomRequestModel *pb.RoomRequestModel) (*pb.RoomCreationResponse, error) {
	return &pb.RoomCreationResponse{
		RoomCreationResponse: getServiceReport(roomRequestModel.RoomRequestModel),
	}, nil
}

func (s *receptionServer) ListRooms(ctx context.Context, empty *emptypb.Empty) (*pb.RoomList, error) {
	return &pb.RoomList{
		Rooms: []*pb.Room{
			{
				Id:          "0cWHPVtqYK1gq34IUieZAYxE",
				Name:        "The cheap one",
				Description: "Oh, you want to save money? look here! what a MEAWESOME room, please be careful about rats and bugs pls... they're really huge KEK.",
				Price:       1,
			},
			{
				Id:          "uiVYozzRgRXF0CyMkfdwCGrI",
				Name:        "The regular one",
				Description: "This is our standard room, good price for non-demanding guests, PURRFECT if you want to optimize value for money :)",
				Price:       50,
			},
			{
				Id:          "47aOlxCtCvBYKNrFdkwtHRsl",
				Name:        "The luxury one",
				Description: "MEAWOUUUUUUUU, you're interested in a very luxury experience! no problem, we have the room for you... if you have enough money ;)",
				Price:       150,
			},
			{
				Id:          "IQXygEah2dI37aOqeBEVYfQ1",
				Name:        "Royal room",
				Description: "MEAWTASTIC your majesty! we have the right room to drain your wallEHM... to meet your high luxury requirements :3",
				Price:       30000,
			},
		},
	}, nil
}

func (s *receptionServer) BookRoom(ctx context.Context, bookingInfo *pb.BookingInfo) (*pb.BookingConfirm, error) {
	return &pb.BookingConfirm{Msg: "Your prenotation is confirmed"}, nil
}
