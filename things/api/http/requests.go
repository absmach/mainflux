// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/things"
)

type createClientReq struct {
	thing things.Client
}

func (req createClientReq) validate() error {
	if len(req.thing.Name) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}
	if req.thing.ID != "" {
		return api.ValidateUUID(req.thing.ID)
	}

	return nil
}

type createClientsReq struct {
	Things []things.Client
}

func (req createClientsReq) validate() error {
	if len(req.Things) == 0 {
		return apiutil.ErrEmptyList
	}
	for _, thing := range req.Things {
		if thing.ID != "" {
			if err := api.ValidateUUID(thing.ID); err != nil {
				return err
			}
		}
		if len(thing.Name) > api.MaxNameSize {
			return apiutil.ErrNameSize
		}
	}

	return nil
}

type viewClientReq struct {
	id string
}

func (req viewClientReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type viewClientPermsReq struct {
	id string
}

func (req viewClientPermsReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type listClientsReq struct {
	status     things.Status
	offset     uint64
	limit      uint64
	name       string
	tag        string
	permission string
	visibility string
	userID     string
	listPerms  bool
	metadata   things.Metadata
	id         string
}

func (req listClientsReq) validate() error {
	if req.limit > api.MaxLimitSize || req.limit < 1 {
		return apiutil.ErrLimitSize
	}
	if req.visibility != "" &&
		req.visibility != api.AllVisibility &&
		req.visibility != api.MyVisibility &&
		req.visibility != api.SharedVisibility {
		return apiutil.ErrInvalidVisibilityType
	}
	if len(req.name) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}

	return nil
}

type listMembersReq struct {
	things.Page
	groupID string
}

func (req listMembersReq) validate() error {
	if req.groupID == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateClientReq struct {
	id       string
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
}

func (req updateClientReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	if len(req.Name) > api.MaxNameSize {
		return apiutil.ErrNameSize
	}

	return nil
}

type updateClientTagsReq struct {
	id   string
	Tags []string `json:"tags,omitempty"`
}

func (req updateClientTagsReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type updateClientCredentialsReq struct {
	id     string
	Secret string `json:"secret,omitempty"`
}

func (req updateClientCredentialsReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	if req.Secret == "" {
		return apiutil.ErrMissingSecret
	}

	return nil
}

type changeClientStatusReq struct {
	id string
}

func (req changeClientStatusReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}

type setThingParentGroupReq struct {
	id            string
	ParentGroupID string `json:"parent_group_id"`
}

func (req setThingParentGroupReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}
	if req.ParentGroupID == "" {
		return apiutil.ErrMissingParentGroupID
	}
	return nil
}

type removeThingParentGroupReq struct {
	id string
}

func (req removeThingParentGroupReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}
	return nil
}

type deleteClientReq struct {
	id string
}

func (req deleteClientReq) validate() error {
	if req.id == "" {
		return apiutil.ErrMissingID
	}

	return nil
}
