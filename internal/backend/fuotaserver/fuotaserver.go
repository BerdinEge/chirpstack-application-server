package fuotaserver

import (
	"fmt"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/brocaar/chirpstack-api/go/v3/fuota"
	"github.com/brocaar/chirpstack-application-server/internal/config"
)

var (
	conn *grpc.ClientConn

	client fuota.FUOTAServerServiceClient
)

// Setup handles the FS client setup.
func Setup(conf *config.Config) error {
	if client != nil {
		return nil
	}

	log.Info("client/as: setup fuota-server client for the first time")

	conn, err := grpc.Dial(conf.FuotaServer.API.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial fuota-server api error: %w", err)
	}

	client = fuota.NewFUOTAServerServiceClient(conn)

	return nil
}

// SetupClient sets the FS client.
func SetupClient() error {

	if err := Setup(&config.C); err != nil {
		return errors.Wrap(err, "setup fuota-server client error")
	}

	return nil
}

func FuotaServiceClient() fuota.FUOTAServerServiceClient {
	return client
}
