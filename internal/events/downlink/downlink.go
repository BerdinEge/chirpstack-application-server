package downlink

import (
	"context"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"time"

	keywrap "github.com/NickBall/go-aes-key-wrap"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/chirpstack-api/go/v3/as"
	pb "github.com/brocaar/chirpstack-api/go/v3/as/integration"
	"github.com/brocaar/chirpstack-api/go/v3/common"
	"github.com/brocaar/chirpstack-application-server/internal/codec"
	"github.com/brocaar/chirpstack-application-server/internal/config"
	"github.com/brocaar/chirpstack-application-server/internal/integration"
	"github.com/brocaar/chirpstack-application-server/internal/logging"
	"github.com/brocaar/chirpstack-application-server/internal/storage"
	"github.com/brocaar/lorawan"
)

type downlinkContext struct {
	downlinkDataReq as.HandleDownlinkDataRequest

	ctx           context.Context
	device        storage.Device
	application   storage.Application
	deviceProfile storage.DeviceProfile

	data       []byte
	objectJSON string
}

var tasks = []func(*downlinkContext) error{
	getDevice,
	getApplication,
	getDeviceProfile,
	//updateDeviceLastSeenAndDR,
	//updateDeviceActivation,
	decryptPayload,
	handleCodec,
	handleIntegrations,
}

// Handle handles the downlink event.
func Handle(ctx context.Context, req as.HandleDownlinkDataRequest) error {
	uc := downlinkContext{
		ctx:             ctx,
		downlinkDataReq: req,
	}

	for _, f := range tasks {
		if err := f(&uc); err != nil {
			if err == ErrAbort {
				return nil
			}
			return err
		}
	}

	return nil
}

func getDevice(ctx *downlinkContext) error {
	var err error
	var devEUI lorawan.EUI64
	copy(devEUI[:], ctx.downlinkDataReq.DevEui)

	ctx.device, err = storage.GetDevice(ctx.ctx, storage.DB(), devEUI, false, true)
	if err != nil {
		return errors.Wrap(err, "get device error")
	}
	return nil
}

func getDeviceProfile(ctx *downlinkContext) error {
	var err error
	ctx.deviceProfile, err = storage.GetDeviceProfile(ctx.ctx, storage.DB(), ctx.device.DeviceProfileID, false, true)
	if err != nil {
		return errors.Wrap(err, "get device-profile error")
	}
	return nil
}

func getApplication(ctx *downlinkContext) error {
	var err error
	ctx.application, err = storage.GetApplication(ctx.ctx, storage.DB(), ctx.device.ApplicationID)
	if err != nil {
		return errors.Wrap(err, "get application error")
	}
	return nil
}

/*func updateDeviceLastSeenAndDR(ctx *downlinkContext) error {
	if err := storage.UpdateDeviceLastSeenAndDR(ctx.ctx, storage.DB(), ctx.device.DevEUI, time.Now(), int(ctx.downlinkDataReq.Dr)); err != nil {
		return errors.Wrap(err, "update device last-seen and dr error")
	}

	return nil
}*/

/*func updateDeviceActivation(ctx *downlinkContext) error {
	da := ctx.downlinkDataReq.DeviceActivationContext

	// nothing to do when there is no new device activation context
	if da == nil {
		return nil
	}

	// key envelope must not be nil
	if da.AppSKey == nil {
		return errors.New("AppSKey must not be nil")
	}

	appSKey, err := unwrapASKey(da.AppSKey)
	if err != nil {
		return errors.Wrap(err, "unwrap AppSKey error")
	}

	var devAddr lorawan.DevAddr
	copy(devAddr[:], da.DevAddr)

	// if DevAddr and AppSKey are equal, there is nothing to do
	if ctx.device.DevAddr == devAddr && ctx.device.AppSKey == appSKey {
		return nil
	}

	ctx.device.DevAddr = devAddr
	ctx.device.AppSKey = appSKey

	if err := storage.UpdateDeviceActivation(ctx.ctx, storage.DB(), ctx.device.DevEUI, ctx.device.DevAddr, ctx.device.AppSKey); err != nil {
		return errors.Wrap(err, "update device activation error")
	}

	pl := pb.JoinEvent{
		ApplicationId:   uint64(ctx.device.ApplicationID),
		ApplicationName: ctx.application.Name,
		DevEui:          ctx.device.DevEUI[:],
		DeviceName:      ctx.device.Name,
		DevAddr:         ctx.device.DevAddr[:],
		RxInfo:          ctx.downlinkDataReq.RxInfo,
		TxInfo:          ctx.downlinkDataReq.TxInfo,
		Dr:              ctx.downlinkDataReq.Dr,
		Tags:            make(map[string]string),
	}

	// set tags
	for k, v := range ctx.device.Tags.Map {
		if v.Valid {
			pl.Tags[k] = v.String
		}
	}

	vars := make(map[string]string)
	for k, v := range ctx.device.Variables.Map {
		if v.Valid {
			vars[k] = v.String
		}
	}

	err = integration.ForApplicationID(ctx.device.ApplicationID).HandleJoinEvent(ctx.ctx, vars, pl)
	if err != nil {
		return errors.Wrap(err, "send join notification error")
	}

	return nil
}*/

func decryptPayload(ctx *downlinkContext) error {
	var err error

	ctx.data, err = lorawan.EncryptFRMPayload(ctx.device.AppSKey, true, ctx.device.DevAddr, ctx.downlinkDataReq.FCnt, ctx.downlinkDataReq.Data)
	if err != nil {
		return errors.Wrap(err, "decrypt payload error")
	}
	return nil
}

func handleCodec(ctx *downlinkContext) error {
	codecType := ctx.application.PayloadCodec
	decoderScript := ctx.application.PayloadDecoderScript

	if ctx.deviceProfile.PayloadCodec != "" {
		codecType = ctx.deviceProfile.PayloadCodec
		decoderScript = ctx.deviceProfile.PayloadDecoderScript
	}

	if codecType == codec.None {
		return nil
	}

	start := time.Now()
	b, err := codec.BinaryToJSON(codecType, uint8(ctx.downlinkDataReq.FPort), ctx.device.Variables, decoderScript, ctx.data)
	if err != nil {
		log.WithFields(log.Fields{
			"codec":          codecType,
			"application_id": ctx.device.ApplicationID,
			"f_port":         ctx.downlinkDataReq.FPort,
			"f_cnt":          ctx.downlinkDataReq.FCnt,
			"dev_eui":        ctx.device.DevEUI,
		}).WithError(err).Error("decode payload error")

		errEvent := pb.ErrorEvent{
			ApplicationId:   uint64(ctx.device.ApplicationID),
			ApplicationName: ctx.application.Name,
			DeviceName:      ctx.device.Name,
			DevEui:          ctx.device.DevEUI[:],
			Type:            pb.ErrorType_DOWNLINK_CODEC,
			Error:           err.Error(),
			FCnt:            ctx.downlinkDataReq.FCnt,
			Tags:            make(map[string]string),
		}

		for k, v := range ctx.device.Tags.Map {
			if v.Valid {
				errEvent.Tags[k] = v.String
			}
		}

		vars := make(map[string]string)
		for k, v := range ctx.device.Variables.Map {
			if v.Valid {
				vars[k] = v.String
			}
		}

		if err := integration.ForApplicationID(ctx.device.ApplicationID).HandleErrorEvent(ctx.ctx, vars, errEvent); err != nil {
			log.WithError(err).Error("send error event to integration error")
		}
	}

	log.WithFields(log.Fields{
		"application_id": ctx.application.ID,
		"codec":          codecType,
		"duration":       time.Since(start),
	}).Debug("payload codec completed Decode execution")

	ctx.objectJSON = string(b)

	return nil
}

func handleIntegrations(ctx *downlinkContext) error {
	pl := pb.DownlinkEvent{
		ApplicationId:     uint64(ctx.device.ApplicationID),
		ApplicationName:   ctx.application.Name,
		DeviceName:        ctx.device.Name,
		DevEui:            ctx.device.DevEUI[:],
		TxInfo:            ctx.downlinkDataReq.TxInfo,
		Dr:                ctx.downlinkDataReq.Dr,
		Adr:               ctx.downlinkDataReq.Adr,
		FCnt:              ctx.downlinkDataReq.FCnt,
		FPort:             ctx.downlinkDataReq.FPort,
		Data:              ctx.data,
		ObjectJson:        ctx.objectJSON,
		Tags:              make(map[string]string),
		ConfirmedDownlink: ctx.downlinkDataReq.ConfirmedDownlink,
		DevAddr:           ctx.device.DevAddr[:],
	}

	// set tags
	for k, v := range ctx.device.Tags.Map {
		if v.Valid {
			pl.Tags[k] = v.String
		}
	}
	vars := make(map[string]string)
	for k, v := range ctx.device.Variables.Map {
		if v.Valid {
			vars[k] = v.String
		}
	}

	bgCtx := context.Background()
	bgCtx = context.WithValue(bgCtx, logging.ContextIDKey, ctx.ctx.Value(logging.ContextIDKey))

	// Handle the actual integration handling in a Go-routine so that the
	// as.HandleDownlinkData api can return.
	go func() {
		err := integration.ForApplicationID(ctx.device.ApplicationID).HandleDownlinkEvent(bgCtx, vars, pl)
		if err != nil {
			log.WithError(err).Error("send downlink event error")
		}
	}()

	return nil
}

func unwrapASKey(ke *common.KeyEnvelope) (lorawan.AES128Key, error) {
	var key lorawan.AES128Key

	if ke.KekLabel == "" {
		copy(key[:], ke.AesKey)
		return key, nil
	}

	for i := range config.C.JoinServer.KEK.Set {
		if config.C.JoinServer.KEK.Set[i].Label == ke.KekLabel {
			kek, err := hex.DecodeString(config.C.JoinServer.KEK.Set[i].KEK)
			if err != nil {
				return key, errors.Wrap(err, "decode kek error")
			}

			block, err := aes.NewCipher(kek)
			if err != nil {
				return key, errors.Wrap(err, "new cipher error")
			}

			b, err := keywrap.Unwrap(block, ke.AesKey)
			if err != nil {
				return key, errors.Wrap(err, "key unwrap error")
			}

			copy(key[:], b)
			return key, nil
		}
	}

	return key, fmt.Errorf("unknown kek label: %s", ke.KekLabel)
}
