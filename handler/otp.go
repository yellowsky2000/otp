package handler

import (
	"context"
	"strings"
	"time"

	"github.com/yellowsky2000/pkg/cache"
	"github.com/yellowsky2000/pkg/tenant"

	admin "github.com/yellowsky2000/pkg/service/proto"

	pb "github.com/yellowsky2000/services/otp/proto"

	pauth "github.com/yellowsky2000/pkg/auth"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"micro.dev/v4/service/errors"
	"micro.dev/v4/service/logger"
)

type Otp struct{}

type OtpKey struct {
	Secret string
	Expiry uint
}

func (e *Otp) Generate(ctx context.Context, req *pb.GenerateRequest, rsp *pb.GenerateResponse) error {
	if len(req.Id) == 0 {
		return errors.BadRequest("otp.generate", "missing id")
	}

	// check if a key exists for the user
	var okey OtpKey
	if req.Expiry <= 0 {
		req.Expiry = 60
	}

	if req.Size <= 0 {
		req.Size = 6
	}

	if _, err := cache.Context(ctx).Get("otp:"+req.Id, &okey); err != nil {
		// generate a key
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Micro",
			AccountName: req.Id,
			Period:      uint(req.Expiry),
			Algorithm:   otp.AlgorithmSHA1,
		})
		if err != nil {
			logger.Error("Failed to generate secret: %v", err)
			return errors.InternalServerError("otp.generate", "failed to generate code")
		}

		okey = OtpKey{
			Secret: key.Secret(),
			Expiry: uint(req.Expiry),
		}

		if err := cache.Context(ctx).Set("otp:"+req.Id, okey, time.Time{}); err != nil {
			logger.Error("Failed to store secret: %v", err)
			return errors.InternalServerError("otp.generate", "failed to generate code")
		}
	}

	logger.Info("generating the code: ", okey.Secret, " ", okey.Expiry)

	// Generate a new code
	code, err := totp.GenerateCodeCustom(okey.Secret, time.Now(), totp.ValidateOpts{
		Period:    uint(req.Expiry),
		Skew:      1,
		Digits:    otp.Digits(req.Size),
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		return errors.InternalServerError("otp.generate", "failed to generate code: %v", err)
	}

	// we have to replace the cache value if the expiry is different
	if v := uint(req.Expiry); v != okey.Expiry {
		okey.Expiry = v

		if err := cache.Context(ctx).Set("otp:"+req.Id, okey, time.Time{}); err != nil {
			logger.Error("Failed to store secret: %v", err)
			return errors.InternalServerError("otp.generate", "failed to generate code")
		}
	}

	// return the code
	rsp.Code = code

	return nil
}

func (e *Otp) Validate(ctx context.Context, req *pb.ValidateRequest, rsp *pb.ValidateResponse) error {
	if len(req.Id) == 0 {
		return errors.BadRequest("otp.generate", "missing id")
	}
	if len(req.Code) == 0 {
		return errors.BadRequest("otp.generate", "missing code")
	}

	key := new(OtpKey)

	if _, err := cache.Context(ctx).Get("otp:"+req.Id, &key); err != nil {
		logger.Error("Failed to get secret from store: %v", err)
		return errors.InternalServerError("otp.generate", "failed to validate")
	}

	logger.Info("validating the code: ", key.Secret, " ", key.Expiry)
	ok, err := totp.ValidateCustom(req.Code, key.Secret, time.Now(), totp.ValidateOpts{
		Period:    key.Expiry,
		Skew:      1,
		Digits:    otp.Digits(len(req.Code)),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return errors.InternalServerError("otp.generate", "failed to validate code")
	}

	// set the response
	rsp.Success = ok

	return nil
}

func (e *Otp) DeleteData(ctx context.Context, request *admin.DeleteDataRequest, response *admin.DeleteDataResponse) error {
	method := "admin.DeleteData"
	_, err := pauth.VerifyMicroAdmin(ctx, method)
	if err != nil {
		return err
	}

	if len(request.TenantId) < 10 { // deliberate length check, so we don't delete all the things
		return errors.BadRequest(method, "Missing tenant ID")
	}

	split := strings.Split(request.TenantId, "/")
	tctx := tenant.NewContext(split[1], split[0], split[1])
	keys, err := cache.Context(ctx).ListKeys()
	if err != nil {
		return err
	}

	for _, k := range keys {
		if err := cache.Context(tctx).Delete(k); err != nil {
			return err
		}
	}
	logger.Infof("Deleted %d keys for %s", len(keys), request.TenantId)

	return nil
}

func (e *Otp) Usage(ctx context.Context, request *admin.UsageRequest, response *admin.UsageResponse) error {
	return nil
}
