// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"

	"github.com/mainflux/mainflux/clients/policies"
	"github.com/mainflux/mainflux/pkg/errors"
	"google.golang.org/grpc"
)

var _ policies.AuthServiceClient = (*authServiceMock)(nil)

type MockSubjectSet struct {
	Object   string
	Relation string
}

type authServiceMock struct {
	users    map[string]string
	policies map[string][]MockSubjectSet
}

func (svc authServiceMock) ListPolicies(ctx context.Context, in *policies.ListPoliciesReq, opts ...grpc.CallOption) (*policies.ListPoliciesRes, error) {
	res := policies.ListPoliciesRes{}
	for key := range svc.policies {
		res.Policies = append(res.Policies, key)
	}
	return &res, nil
}

// NewAuthService creates mock of users service.
func NewAuthService(users map[string]string, policies map[string][]MockSubjectSet) policies.AuthServiceClient {
	return &authServiceMock{users, policies}
}

func (svc authServiceMock) Identify(ctx context.Context, in *policies.Token, opts ...grpc.CallOption) (*policies.UserIdentity, error) {
	if id, ok := svc.users[in.Value]; ok {
		return &policies.UserIdentity{Id: id, Email: id}, nil
	}
	return nil, errors.ErrAuthentication
}

func (svc authServiceMock) Issue(ctx context.Context, in *policies.IssueReq, opts ...grpc.CallOption) (*policies.Token, error) {
	if id, ok := svc.users[in.GetEmail()]; ok {
		switch in.Type {
		default:
			return &policies.Token{Value: id}, nil
		}
	}
	return nil, errors.ErrAuthentication
}

func (svc authServiceMock) Authorize(ctx context.Context, req *policies.AuthorizeReq, _ ...grpc.CallOption) (r *policies.AuthorizeRes, err error) {
	for _, policy := range svc.policies[req.GetSub()] {
		if policy.Relation == req.GetAct() && policy.Object == req.GetObj() {
			return &policies.AuthorizeRes{Authorized: true}, nil
		}
	}
	return nil, errors.ErrAuthorization
}

func (svc authServiceMock) AddPolicy(ctx context.Context, in *policies.AddPolicyReq, opts ...grpc.CallOption) (*policies.AddPolicyRes, error) {
	if in.GetAct() == "" || in.GetObj() == "" || in.GetSub() == "" {
		return &policies.AddPolicyRes{}, errors.ErrMalformedEntity
	}

	obj := in.GetObj()
	svc.policies[in.GetSub()] = append(svc.policies[in.GetSub()], MockSubjectSet{Object: obj, Relation: in.GetAct()})
	return &policies.AddPolicyRes{Authorized: true}, nil
}

func (svc authServiceMock) DeletePolicy(ctx context.Context, in *policies.DeletePolicyReq, opts ...grpc.CallOption) (*policies.DeletePolicyRes, error) {
	// Not implemented yet
	return &policies.DeletePolicyRes{Deleted: true}, nil
}
