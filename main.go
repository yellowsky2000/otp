package main

import (
	"github.com/yellowsky2000/otp/handler"
	pb "github.com/yellowsky2000/otp/proto"

	adminpb "github.com/yellowsky2000/pkg/service/proto"

	"micro.dev/v4/service"
	"micro.dev/v4/service/logger"
)

func main() {
	// Create service
	srv := service.New(
		service.Name("otp"),
	)

	h := new(handler.Otp)
	// Register handler
	pb.RegisterOtpHandler(srv.Server(), h)
	adminpb.RegisterAdminHandler(srv.Server(), h)

	// Run service
	if err := srv.Run(); err != nil {
		logger.Fatal(err)
	}
}
