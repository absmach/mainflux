// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"time"

	"github.com/absmach/supermq/clients"
	"github.com/absmach/supermq/pkg/events"
	"github.com/absmach/supermq/pkg/roles"
)

const (
	clientPrefix       = "client."
	clientCreate       = clientPrefix + "create"
	clientUpdate       = clientPrefix + "update"
	clientChangeStatus = clientPrefix + "change_status"
	clientRemove       = clientPrefix + "remove"
	clientView         = clientPrefix + "view"
	clientViewPerms    = clientPrefix + "view_perms"
	clientList         = clientPrefix + "list"
	clientListByGroup  = clientPrefix + "list_by_channel"
	clientIdentify     = clientPrefix + "identify"
	clientAuthorize    = clientPrefix + "authorize"
	clientSetParent    = clientPrefix + "set_parent"
	clientRemoveParent = clientPrefix + "remove_parent"
)

var (
	_ events.Event = (*createClientEvent)(nil)
	_ events.Event = (*updateClientEvent)(nil)
	_ events.Event = (*changeStatusClientEvent)(nil)
	_ events.Event = (*viewClientEvent)(nil)
	_ events.Event = (*viewClientPermsEvent)(nil)
	_ events.Event = (*listClientEvent)(nil)
	_ events.Event = (*listClientByGroupEvent)(nil)
	_ events.Event = (*identifyClientEvent)(nil)
	_ events.Event = (*authorizeClientEvent)(nil)
	_ events.Event = (*shareClientEvent)(nil)
	_ events.Event = (*removeClientEvent)(nil)
)

type createClientEvent struct {
	domainID string
	clients.Client
	rolesProvisioned []roles.RoleProvision
}

func (cce createClientEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":         clientCreate,
		"id":                cce.ID,
		"roles_provisioned": cce.rolesProvisioned,
		"status":            cce.Status.String(),
		"created_at":        cce.CreatedAt,
		"domain":            cce.domainID,
	}

	if cce.Name != "" {
		val["name"] = cce.Name
	}
	if len(cce.Tags) > 0 {
		val["tags"] = cce.Tags
	}
	if cce.Metadata != nil {
		val["metadata"] = cce.Metadata
	}
	if cce.Credentials.Identity != "" {
		val["identity"] = cce.Credentials.Identity
	}

	return val, nil
}

type updateClientEvent struct {
	clients.Client
	operation string
	domainID  string
}

func (uce updateClientEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  clientUpdate,
		"updated_at": uce.UpdatedAt,
		"updated_by": uce.UpdatedBy,
		"domain":     uce.domainID,
	}
	if uce.operation != "" {
		val["operation"] = clientUpdate + "_" + uce.operation
	}

	if uce.ID != "" {
		val["id"] = uce.ID
	}
	if uce.Name != "" {
		val["name"] = uce.Name
	}
	if len(uce.Tags) > 0 {
		val["tags"] = uce.Tags
	}
	if uce.Credentials.Identity != "" {
		val["identity"] = uce.Credentials.Identity
	}
	if uce.Metadata != nil {
		val["metadata"] = uce.Metadata
	}
	if !uce.CreatedAt.IsZero() {
		val["created_at"] = uce.CreatedAt
	}
	if uce.Status.String() != "" {
		val["status"] = uce.Status.String()
	}

	return val, nil
}

type changeStatusClientEvent struct {
	id        string
	status    string
	updatedAt time.Time
	updatedBy string
	domainID  string
}

func (rce changeStatusClientEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":  clientChangeStatus,
		"id":         rce.id,
		"status":     rce.status,
		"updated_at": rce.updatedAt,
		"updated_by": rce.updatedBy,
		"domain":     rce.domainID,
	}, nil
}

type viewClientEvent struct {
	domainID string
	clients.Client
}

func (vce viewClientEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation": clientView,
		"id":        vce.ID,
		"domain":    vce.domainID,
	}

	if vce.Name != "" {
		val["name"] = vce.Name
	}
	if len(vce.Tags) > 0 {
		val["tags"] = vce.Tags
	}
	if vce.Credentials.Identity != "" {
		val["identity"] = vce.Credentials.Identity
	}
	if vce.Metadata != nil {
		val["metadata"] = vce.Metadata
	}
	if !vce.CreatedAt.IsZero() {
		val["created_at"] = vce.CreatedAt
	}
	if !vce.UpdatedAt.IsZero() {
		val["updated_at"] = vce.UpdatedAt
	}
	if vce.UpdatedBy != "" {
		val["updated_by"] = vce.UpdatedBy
	}
	if vce.Status.String() != "" {
		val["status"] = vce.Status.String()
	}

	return val, nil
}

type viewClientPermsEvent struct {
	permissions []string
	domainID    string
}

func (vcpe viewClientPermsEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":   clientViewPerms,
		"permissions": vcpe.permissions,
		"domain":      vcpe.domainID,
	}
	return val, nil
}

type listClientEvent struct {
	domainID  string
	reqUserID string
	clients.Page
}

func (lce listClientEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation": clientList,
		"reqUserID": lce.reqUserID,
		"total":     lce.Total,
		"offset":    lce.Offset,
		"limit":     lce.Limit,
		"domain":    lce.domainID,
	}

	if lce.Name != "" {
		val["name"] = lce.Name
	}
	if lce.Order != "" {
		val["order"] = lce.Order
	}
	if lce.Dir != "" {
		val["dir"] = lce.Dir
	}
	if lce.Metadata != nil {
		val["metadata"] = lce.Metadata
	}
	if lce.Tag != "" {
		val["tag"] = lce.Tag
	}
	if lce.Permission != "" {
		val["permission"] = lce.Permission
	}
	if lce.Status.String() != "" {
		val["status"] = lce.Status.String()
	}
	if len(lce.IDs) > 0 {
		val["ids"] = lce.IDs
	}
	if lce.Identity != "" {
		val["identity"] = lce.Identity
	}

	return val, nil
}

type listClientByGroupEvent struct {
	clients.Page
	channelID string
	domainID  string
}

func (lcge listClientByGroupEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  clientListByGroup,
		"total":      lcge.Total,
		"offset":     lcge.Offset,
		"limit":      lcge.Limit,
		"channel_id": lcge.channelID,
		"domain":     lcge.domainID,
	}

	if lcge.Name != "" {
		val["name"] = lcge.Name
	}
	if lcge.Order != "" {
		val["order"] = lcge.Order
	}
	if lcge.Dir != "" {
		val["dir"] = lcge.Dir
	}
	if lcge.Metadata != nil {
		val["metadata"] = lcge.Metadata
	}
	if lcge.Tag != "" {
		val["tag"] = lcge.Tag
	}
	if lcge.Permission != "" {
		val["permission"] = lcge.Permission
	}
	if lcge.Status.String() != "" {
		val["status"] = lcge.Status.String()
	}
	if lcge.Identity != "" {
		val["identity"] = lcge.Identity
	}

	return val, nil
}

type identifyClientEvent struct {
	domainID string
	clientID string
}

func (ice identifyClientEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation": clientIdentify,
		"id":        ice.clientID,
		"domain":    ice.domainID,
	}, nil
}

type authorizeClientEvent struct {
	clientID   string
	channelID  string
	permission string
	domainID   string
}

func (ice authorizeClientEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation": clientAuthorize,
		"id":        ice.clientID,
		"domain":    ice.domainID,
	}

	if ice.permission != "" {
		val["permission"] = ice.permission
	}
	if ice.channelID != "" {
		val["channelID"] = ice.channelID
	}

	return val, nil
}

type shareClientEvent struct {
	domainID string
	action   string
	id       string
	relation string
	userIDs  []string
}

func (sce shareClientEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation": clientPrefix + sce.action,
		"id":        sce.id,
		"relation":  sce.relation,
		"user_ids":  sce.userIDs,
		"domain":    sce.domainID,
	}, nil
}

type removeClientEvent struct {
	domainID string
	id       string
}

func (dce removeClientEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation": clientRemove,
		"id":        dce.id,
		"domain":    dce.domainID,
	}, nil
}

type setParentGroupEvent struct {
	id            string
	parentGroupID string
	domainID      string
}

func (spge setParentGroupEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":       clientSetParent,
		"id":              spge.id,
		"parent_group_id": spge.parentGroupID,
		"domain":          spge.domainID,
	}, nil
}

type removeParentGroupEvent struct {
	id       string
	domainID string
}

func (rpge removeParentGroupEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation": clientRemoveParent,
		"id":        rpge.id,
		"domain":    rpge.domainID,
	}, nil
}
