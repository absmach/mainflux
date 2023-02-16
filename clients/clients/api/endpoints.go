package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/clients/clients"
)

func registrationEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createClientReq)
		if err := req.validate(); err != nil {
			return createClientRes{}, err
		}
		client, err := svc.RegisterClient(ctx, req.token, req.client)
		if err != nil {
			return createClientRes{}, err
		}
		ucr := createClientRes{
			Client:  client,
			created: true,
		}

		return ucr, nil
	}
}

func viewClientEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewClientReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		c, err := svc.ViewClient(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return viewClientRes{Client: c}, nil
	}
}

func listClientsEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listClientsReq)
		if err := req.validate(); err != nil {
			return clients.ClientsPage{}, err
		}

		pm := clients.Page{
			SharedBy: req.sharedBy,
			Status:   req.status,
			Offset:   req.offset,
			Limit:    req.limit,
			OwnerID:  req.owner,
			Name:     req.name,
			Tag:      req.tag,
			Metadata: req.metadata,
		}
		page, err := svc.ListClients(ctx, req.token, pm)
		if err != nil {
			return clients.ClientsPage{}, err
		}

		res := clientsPageRes{
			pageRes: pageRes{
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

func listMembersEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersReq)
		if err := req.validate(); err != nil {
			return memberPageRes{}, err
		}
		page, err := svc.ListMembers(ctx, req.token, req.groupID, req.Page)
		if err != nil {
			return memberPageRes{}, err
		}
		return buildMembersResponse(page), nil
	}
}

func updateClientEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cli := clients.Client{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		client, err := svc.UpdateClient(ctx, req.token, cli)
		if err != nil {
			return nil, err
		}
		return updateClientRes{Client: client}, nil
	}
}

func updateClientTagsEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientTagsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cli := clients.Client{
			ID:   req.id,
			Tags: req.Tags,
		}
		client, err := svc.UpdateClientTags(ctx, req.token, cli)
		if err != nil {
			return nil, err
		}
		return updateClientRes{Client: client}, nil
	}
}

func updateClientIdentityEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientCredentialsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		client, err := svc.UpdateClientIdentity(ctx, req.token, req.id, req.Identity)
		if err != nil {
			return nil, err
		}
		return updateClientRes{Client: client}, nil
	}
}

func updateClientSecretEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientCredentialsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		client, err := svc.UpdateClientSecret(ctx, req.token, req.OldSecret, req.NewSecret)
		if err != nil {
			return nil, err
		}
		return updateClientRes{Client: client}, nil
	}
}

func updateClientOwnerEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateClientOwnerReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cli := clients.Client{
			ID:    req.id,
			Owner: req.Owner,
		}

		client, err := svc.UpdateClientOwner(ctx, req.token, cli)
		if err != nil {
			return nil, err
		}
		return updateClientRes{Client: client}, nil
	}
}

func issueTokenEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(loginClientReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.IssueToken(ctx, req.Identity, req.Secret)
		if err != nil {
			return nil, err
		}

		return tokenRes{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			AccessType:   token.AccessType,
		}, nil
	}
}

func refreshTokenEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.RefreshToken(ctx, req.RefreshToken)
		if err != nil {
			return nil, err
		}

		return tokenRes{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			AccessType:   token.AccessType,
		}, nil
	}
}

func enableClientEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeClientStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		client, err := svc.EnableClient(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return deleteClientRes{Client: client}, nil
	}
}

func disableClientEndpoint(svc clients.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(changeClientStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		client, err := svc.DisableClient(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return deleteClientRes{Client: client}, nil
	}
}

func buildMembersResponse(cp clients.MembersPage) memberPageRes {
	res := memberPageRes{
		pageRes: pageRes{
			Total:  cp.Total,
			Offset: cp.Offset,
			Limit:  cp.Limit,
		},
		Members: []viewMembersRes{},
	}
	for _, c := range cp.Members {
		res.Members = append(res.Members, viewMembersRes{Client: c})
	}
	return res
}
