package groups

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/auth"
	groups "github.com/mainflux/mainflux/auth"
	"github.com/mainflux/mainflux/pkg/errors"
)

func CreateGroupEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createGroupReq)
		if err := req.validate(); err != nil {
			return groupRes{}, err
		}

		group := groups.Group{
			Name:        req.Name,
			Description: req.Description,
			ParentID:    req.ParentID,
			Metadata:    req.Metadata,
		}

		group, err := svc.CreateGroup(ctx, req.token, group)
		if err != nil {
			return groupRes{}, errors.Wrap(groups.ErrCreateGroup, err)
		}

		return groupRes{created: true, id: group.ID}, nil
	}
}

func ViewGroupEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(groupReq)
		if err := req.validate(); err != nil {
			return viewGroupRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}

		group, err := svc.ViewGroup(ctx, req.token, req.id)
		if err != nil {
			return viewGroupRes{}, errors.Wrap(groups.ErrFetchGroups, err)
		}

		res := viewGroupRes{
			ID:          group.ID,
			Name:        group.Name,
			Description: group.Description,
			Metadata:    group.Metadata,
			ParentID:    group.ParentID,
			OwnerID:     group.OwnerID,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		}

		return res, nil
	}
}

func UpdateGroupEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupReq)
		if err := req.validate(); err != nil {
			return groupRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}

		group := groups.Group{
			ID:          req.id,
			Name:        req.Name,
			Description: req.Description,
			ParentID:    req.ParentID,
			Metadata:    req.Metadata,
		}

		_, err := svc.UpdateGroup(ctx, req.token, group)
		if err != nil {
			return groupRes{}, errors.Wrap(groups.ErrUpdateGroup, err)
		}

		res := groupRes{created: false}
		return res, nil
	}
}

func DeleteGroupEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(groupReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(groups.ErrMalformedEntity, err)
		}

		if err := svc.RemoveGroup(ctx, req.token, req.id); err != nil {
			return nil, errors.Wrap(groups.ErrDeleteGroup, err)
		}

		return groupDeleteRes{}, nil
	}
}

func ListGroupsEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listGroupsReq)
		if err := req.validate(); err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}
		pm := auth.PageMetadata{
			Level:    req.level,
			Metadata: req.metadata,
		}
		page, err := svc.ListGroups(ctx, req.token, pm)
		if err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrFetchGroups, err)
		}

		if req.tree {
			return buildGroupsResponseTree(page), nil
		}

		return buildGroupsResponse(page), nil
	}
}

func ListMemberships(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembershipReq)
		if err := req.validate(); err != nil {
			return memberPageRes{}, err
		}

		pm := auth.PageMetadata{
			Offset:   req.offset,
			Limit:    req.limit,
			Metadata: req.metadata,
		}

		page, err := svc.ListMemberships(ctx, req.token, req.id, pm)
		if err != nil {
			return memberPageRes{}, err
		}

		if req.tree {
			return buildGroupsResponseTree(page), nil
		}

		return buildGroupsResponse(page), nil
	}
}

func ListGroupChildrenEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listGroupsReq)
		if err := req.validate(); err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}

		pm := auth.PageMetadata{
			Level:    req.level,
			Metadata: req.metadata,
		}
		page, err := svc.ListChildren(ctx, req.token, req.id, pm)
		if err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrFetchGroups, err)
		}

		if req.tree {
			return buildGroupsResponseTree(page), nil
		}

		return buildGroupsResponse(page), nil
	}
}

func ListGroupParentsEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listGroupsReq)
		if err := req.validate(); err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}
		pm := auth.PageMetadata{
			Level:    req.level,
			Metadata: req.metadata,
		}

		page, err := svc.ListParents(ctx, req.token, req.id, pm)
		if err != nil {
			return groupPageRes{}, errors.Wrap(groups.ErrFetchGroups, err)
		}

		if req.tree {
			return buildGroupsResponseTree(page), nil
		}

		return buildGroupsResponse(page), nil
	}
}

func AssignEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMembersGroupReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(groups.ErrMalformedEntity, err)
		}
		var ids []string
		for _, id := range req.Members {
			ids = append(ids, id)
		}
		if err := svc.Assign(ctx, req.token, req.groupID, req.groupType, ids...); err != nil {
			return nil, errors.Wrap(groups.ErrAssignToGroup, err)
		}

		return assignMemberToGroupRes{}, nil
	}
}

func UnassignEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMembersGroupReq)
		if err := req.validate(); err != nil {
			return nil, errors.Wrap(groups.ErrMalformedEntity, err)
		}
		var ids []string
		for _, id := range req.Members {
			ids = append(ids, id)
		}
		if err := svc.Unassign(ctx, req.token, req.groupID, ids...); err != nil {
			return nil, errors.Wrap(groups.ErrUnassignFromGroup, err)
		}

		return removeMemberFromGroupRes{}, nil
	}
}

func ListMembersEndpoint(svc groups.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listMembersReq)
		if err := req.validate(); err != nil {
			return memberPageRes{}, errors.Wrap(groups.ErrMalformedEntity, err)
		}

		pm := auth.PageMetadata{
			Offset:   req.offset,
			Limit:    req.limit,
			Metadata: req.metadata,
		}
		page, err := svc.ListMembers(ctx, req.token, req.id, req.groupType, pm)
		if err != nil {
			return memberPageRes{}, err
		}

		return buildUsersResponse(page), nil
	}
}

func buildGroupsResponseTree(page auth.GroupPage) groupPageRes {
	groupsMap := map[string]*groups.Group{}
	// Parents map keeps its array of children.
	parentsMap := map[string][]*groups.Group{}
	for i := range page.Groups {
		if _, ok := groupsMap[page.Groups[i].ID]; !ok {
			groupsMap[page.Groups[i].ID] = &page.Groups[i]
			parentsMap[page.Groups[i].ID] = make([]*groups.Group, 0)
		}
	}

	for _, group := range groupsMap {
		if ch, ok := parentsMap[group.ParentID]; ok {
			ch = append(ch, group)
			parentsMap[group.ParentID] = ch
		}
	}

	res := groupPageRes{
		Total:  page.Total,
		Level:  page.Level,
		Groups: []viewGroupRes{},
	}

	for _, group := range groupsMap {
		if children, ok := parentsMap[group.ID]; ok {
			group.Children = children
		}

	}

	for _, group := range groupsMap {
		view := toViewGroupRes(*group)
		if children, ok := parentsMap[group.ParentID]; len(children) == 0 || !ok {
			res.Groups = append(res.Groups, view)
		}
	}

	return res
}

func toViewGroupRes(group auth.Group) viewGroupRes {
	view := viewGroupRes{
		ID:          group.ID,
		ParentID:    group.ParentID,
		OwnerID:     group.OwnerID,
		Name:        group.Name,
		Description: group.Description,
		Metadata:    group.Metadata,
		Level:       group.Level,
		Path:        group.Path,
		Children:    make([]*viewGroupRes, 0),
		CreatedAt:   group.CreatedAt,
		UpdatedAt:   group.UpdatedAt,
	}

	for _, ch := range group.Children {
		child := toViewGroupRes(*ch)
		view.Children = append(view.Children, &child)
	}

	return view
}

func buildGroupsResponse(gp auth.GroupPage) groupPageRes {
	res := groupPageRes{
		Total:  gp.Total,
		Level:  gp.Level,
		Groups: []viewGroupRes{},
	}

	for _, group := range gp.Groups {
		view := viewGroupRes{
			ID:          group.ID,
			ParentID:    group.ParentID,
			OwnerID:     group.OwnerID,
			Name:        group.Name,
			Description: group.Description,
			Metadata:    group.Metadata,
			Level:       group.Level,
			Path:        group.Path,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		}
		res.Groups = append(res.Groups, view)
	}

	return res
}

func buildUsersResponse(mp auth.MemberPage) memberPageRes {
	res := memberPageRes{
		pageRes: pageRes{
			Total:  mp.Total,
			Offset: mp.Offset,
			Limit:  mp.Limit,
			Name:   mp.Name,
		},
		Members: []interface{}{},
	}

	for _, m := range mp.Members {
		res.Members = append(res.Members, m)
	}

	return res
}
