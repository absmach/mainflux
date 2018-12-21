package http

import (
	"context"
	"nov/bootstrap"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/things"
)

func addEndpoint(svc bootstrap.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(addReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		thing := bootstrap.Thing{
			ExternalID: req.ExternalID,
		}
		saved, err := svc.Add(req.key, thing)
		if err != nil {
			return nil, err
		}

		res := thingRes{
			id:      saved.ID,
			created: true,
		}
		return res, nil
	}
}

func bootstrapEndpoint(svc bootstrap.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(boostrapReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Bootstrap(req.externalID); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func viewEndpoint(svc bootstrap.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		thing, err := svc.View(req.key, req.id)
		if err != nil {
			return nil, err
		}

		res := viewRes{
			ID:         thing.ID,
			Key:        thing.Key,
			Owner:      thing.Owner,
			MainfluxID: thing.MainfluxID,
			ExternalID: thing.ExternalID,
			Status:     thing.Status,
		}
		return res, nil
	}
}

func removeEndpoint(svc bootstrap.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)

		err := req.validate()
		if err == things.ErrNotFound {
			return removeRes{}, nil
		}

		if err != nil {
			return nil, err
		}

		if err := svc.Remove(req.key, req.id); err != nil {
			return nil, err
		}

		return removeRes{}, nil
	}
}

func statusEndpoint(svc bootstrap.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(changeStatusReq)

		err := req.validate()
		if err == things.ErrNotFound {
			return removeRes{}, nil
		}

		if err != nil {
			return nil, err
		}

		if err := svc.ChangeStatus(req.Key, req.key, req.Status); err != nil {
			return nil, err
		}

		return removeRes{}, nil
	}
}
