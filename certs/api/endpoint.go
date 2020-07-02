package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/certs"
)

func issueCert(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(addCertsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.IssueCert(ctx, req.token, req.ThingID, req.Valid, req.KeyBits, req.KeyType)
		if err != nil {
			return certsResponse{Error: err.Error()}, nil
		}
		return res, nil
	}
}
func viewCert(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		page, err := svc.ViewCert(ctx, req.token, req.ownerID, req.offset, req.limit)
		if err != nil {
			return certsPageRes{
				Error: err.Error(),
			}, err
		}

	}
}
func listCerts(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		page, err := svc.ListCerts(ctx, req.token, req.ownerID, req.offset, req.limit)
		if err != nil {
			return certsPageRes{
				Error: err.Error(),
			}, err
		}
		res := certsPageRes{
			pageRes: pageRes{
				Total:  page.Total,
				Offset: page.Offset,
				Limit:  page.Limit,
			},
			Certs: []certsResponse{},
		}

		for _, cert := range page.Certs {
			view := certsResponse{
				Serial:  cert.Serial,
				ThingID: cert.ThingID,
			}
			res.Certs = append(res.Certs, view)
		}
		return res, nil
	}
}

func revokeCert(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(revokeReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		return svc.RevokeCert(ctx, req.token, req.ThingID, req.CertSerial)
	}
}
