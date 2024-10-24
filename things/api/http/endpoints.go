// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"

	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/authn"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/things"
	"github.com/go-kit/kit/endpoint"
)

func createClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createClientReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		thing, err := svc.CreateClients(ctx, session, req.thing)
		if err != nil {
			return nil, err
		}

		return createClientRes{
			Client:  thing[0],
			created: true,
		}, nil
	}
}

func createClientsEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createClientsReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		page, err := svc.CreateClients(ctx, session, req.Things...)
		if err != nil {
			return nil, err
		}

		res := clientsPageRes{
			clientsPageMetaRes: clientsPageMetaRes{
				Total: uint64(len(page)),
			},
			Clients: []viewClientRes{},
		}
		for _, c := range page {
			res.Clients = append(res.Clients, viewClientRes{Client: c})
		}

		return res, nil
	}
}

func viewClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewClientReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		c, err := svc.View(ctx, session, req.id)
		if err != nil {
			return nil, err
		}

		return viewClientRes{Client: c}, nil
	}
}

func listClientsEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listClientsReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		pm := things.Page{
			Status:     req.status,
			Offset:     req.offset,
			Limit:      req.limit,
			Name:       req.name,
			Tag:        req.tag,
			Permission: req.permission,
			Metadata:   req.metadata,
			ListPerms:  req.listPerms,
			Id:         req.id,
		}
		page, err := svc.ListClients(ctx, session, req.userID, pm)
		if err != nil {
			return nil, err
		}

		res := clientsPageRes{
			clientsPageMetaRes: clientsPageMetaRes{
				Total:  page.Total,
				Offset: page.Offset,
				Limit:  page.Limit,
			},
			Clients: []viewClientRes{},
		}
		for _, c := range page.Clients {
			res.Clients = append(res.Clients, viewClientRes{Client: c})
		}

		return res, nil
	}
}

func updateClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		cli := things.Client{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		client, err := svc.Update(ctx, session, cli)
		if err != nil {
			return nil, err
		}

		return updateClientRes{Client: client}, nil
	}
}

func updateClientTagsEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientTagsReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		cli := things.Client{
			ID:   req.id,
			Tags: req.Tags,
		}
		client, err := svc.UpdateTags(ctx, session, cli)
		if err != nil {
			return nil, err
		}

		return updateClientRes{Client: client}, nil
	}
}

func updateClientSecretEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientCredentialsReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		client, err := svc.UpdateSecret(ctx, session, req.id, req.Secret)
		if err != nil {
			return nil, err
		}

		return updateClientRes{Client: client}, nil
	}
}

func enableClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeClientStatusReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		client, err := svc.Enable(ctx, session, req.id)
		if err != nil {
			return nil, err
		}

		return changeClientStatusRes{Client: client}, nil
	}
}

func disableClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeClientStatusReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		client, err := svc.Disable(ctx, session, req.id)
		if err != nil {
			return nil, err
		}

		return changeClientStatusRes{Client: client}, nil
	}
}

func buildClientsResponse(cp things.MembersPage) clientsPageRes {
	res := clientsPageRes{
		clientsPageMetaRes: clientsPageMetaRes{
			Total:  cp.Total,
			Offset: cp.Offset,
			Limit:  cp.Limit,
		},
		Clients: []viewClientRes{},
	}
	for _, c := range cp.Members {
		res.Clients = append(res.Clients, viewClientRes{Client: c})
	}

	return res
}

func setThingParentGroupEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(setThingParentGroupReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}
		if err := svc.SetParentGroup(ctx, session, req.ParentGroupID, req.id); err != nil {
			return nil, err
		}

		return setParentGroupRes{}, nil
	}
}

func removeThingParentGroupEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(removeThingParentGroupReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}
		if err := svc.RemoveParentGroup(ctx, session, req.id); err != nil {
			return nil, err
		}

		return removeParentGroupRes{}, nil
	}
}

func deleteClientEndpoint(svc things.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteClientReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(apiutil.ErrValidation, err)
		}

		session, ok := ctx.Value(api.SessionKey).(authn.Session)
		if !ok {
			return nil, svcerr.ErrAuthentication
		}

		if err := svc.Delete(ctx, session, req.id); err != nil {
			return nil, err
		}

		return deleteClientRes{}, nil
	}
}
