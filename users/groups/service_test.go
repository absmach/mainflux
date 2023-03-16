package groups_test

import (
	context "context"
	fmt "fmt"
	"regexp"
	"testing"
	"time"

	"github.com/mainflux/mainflux/internal/testsutil"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/mainflux/mainflux/users/clients"
	cmocks "github.com/mainflux/mainflux/users/clients/mocks"
	"github.com/mainflux/mainflux/users/groups"
	"github.com/mainflux/mainflux/users/groups/mocks"
	gmocks "github.com/mainflux/mainflux/users/groups/mocks"
	"github.com/mainflux/mainflux/users/hasher"
	"github.com/mainflux/mainflux/users/jwt"
	pmocks "github.com/mainflux/mainflux/users/policies/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	idProvider     = uuid.New()
	phasher        = hasher.New()
	secret         = "strongsecret"
	validGMetadata = groups.Metadata{"role": "client"}
	inValidToken   = "invalidToken"
	description    = "shortdescription"
	gName          = "groupname"
	group          = groups.Group{
		Name:        gName,
		Description: description,
		Metadata:    validGMetadata,
		Status:      groups.EnabledStatus,
	}
	withinDuration  = 5 * time.Second
	passRegex       = regexp.MustCompile("^.{8,}$")
	accessDuration  = time.Minute * 1
	refreshDuration = time.Minute * 10
)

func TestCreateGroup(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	cases := []struct {
		desc  string
		group groups.Group
		err   error
	}{
		{
			desc:  "create new group",
			group: group,
			err:   nil,
		},
		{
			desc:  "create group with existing name",
			group: group,
			err:   nil,
		},
		{
			desc: "create group with parent",
			group: groups.Group{
				Name:     gName,
				ParentID: testsutil.GenerateUUID(t, idProvider),
				Status:   groups.EnabledStatus,
			},
			err: nil,
		},
		{
			desc: "create group with invalid parent",
			group: groups.Group{
				Name:     gName,
				ParentID: mocks.WrongID,
			},
			err: errors.ErrCreateEntity,
		},
		{
			desc: "create group with invalid owner",
			group: groups.Group{
				Name:    gName,
				OwnerID: mocks.WrongID,
			},
			err: errors.ErrCreateEntity,
		},
		{
			desc:  "create group with missing name",
			group: groups.Group{},
			err:   errors.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		repoCall := gRepo.On("Save", context.Background(), mock.Anything).Return(tc.group, tc.err)
		createdAt := time.Now()
		expected, err := svc.CreateGroup(context.Background(), testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher), tc.group)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if err == nil {
			assert.NotEmpty(t, expected.ID, fmt.Sprintf("%s: expected %s not to be empty\n", tc.desc, expected.ID))
			assert.WithinDuration(t, expected.CreatedAt, createdAt, withinDuration, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected.CreatedAt, createdAt))
			tc.group.ID = expected.ID
			tc.group.CreatedAt = expected.CreatedAt
			tc.group.UpdatedAt = expected.UpdatedAt
			tc.group.OwnerID = expected.OwnerID
			assert.Equal(t, tc.group, expected, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.group, expected))
			ok := repoCall.Parent.AssertCalled(t, "Save", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Save was not called on %s", tc.desc))
		}
		repoCall.Unset()
	}
}

func TestUpdateGroup(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	group.ID = testsutil.GenerateUUID(t, idProvider)

	cases := []struct {
		desc     string
		token    string
		group    groups.Group
		response groups.Group
		err      error
	}{
		{
			desc: "update group name",
			group: groups.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			response: groups.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			token: testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:   nil,
		},
		{
			desc: "update group description",
			group: groups.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			response: groups.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			token: testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:   nil,
		},
		{
			desc: "update group metadata",
			group: groups.Group{
				ID: group.ID,
				Metadata: groups.Metadata{
					"field": "value2",
				},
			},
			response: groups.Group{
				ID: group.ID,
				Metadata: groups.Metadata{
					"field": "value2",
				},
			},
			token: testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:   nil,
		},
		{
			desc: "update group name with invalid group id",
			group: groups.Group{
				ID:   mocks.WrongID,
				Name: "NewName",
			},
			response: groups.Group{},
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group description with invalid group id",
			group: groups.Group{
				ID:          mocks.WrongID,
				Description: "NewDescription",
			},
			response: groups.Group{},
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group metadata with invalid group id",
			group: groups.Group{
				ID: mocks.WrongID,
				Metadata: groups.Metadata{
					"field": "value2",
				},
			},
			response: groups.Group{},
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			err:      errors.ErrNotFound,
		},
		{
			desc: "update group name with invalid token",
			group: groups.Group{
				ID:   group.ID,
				Name: "NewName",
			},
			response: groups.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update group description with invalid token",
			group: groups.Group{
				ID:          group.ID,
				Description: "NewDescription",
			},
			response: groups.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
		{
			desc: "update group metadata with invalid token",
			group: groups.Group{
				ID: group.ID,
				Metadata: groups.Metadata{
					"field": "value2",
				},
			},
			response: groups.Group{},
			token:    inValidToken,
			err:      errors.ErrAuthentication,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("CheckAdmin", context.Background(), mock.Anything).Return(nil)
		repoCall1 := gRepo.On("Update", context.Background(), mock.Anything).Return(tc.response, tc.err)
		expectedGroup, err := svc.UpdateGroup(context.Background(), tc.token, tc.group)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, expectedGroup, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, expectedGroup))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "CheckAdmin", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("CheckAdmin was not called on %s", tc.desc))
			ok = repoCall1.Parent.AssertCalled(t, "Update", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("Update was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
	}

}

func TestViewGroup(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	group.ID = testsutil.GenerateUUID(t, idProvider)

	cases := []struct {
		desc     string
		token    string
		groupID  string
		response groups.Group
		err      error
	}{
		{

			desc:     "view group",
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			groupID:  group.ID,
			response: group,
			err:      nil,
		},
		{
			desc:     "view group with invalid token",
			token:    "wrongtoken",
			groupID:  group.ID,
			response: groups.Group{},
			err:      errors.ErrAuthentication,
		},
		{
			desc:     "view group for wrong id",
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			groupID:  mocks.WrongID,
			response: groups.Group{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("CheckAdmin", context.Background(), mock.Anything).Return(nil)
		repoCall1 := gRepo.On("RetrieveByID", context.Background(), tc.groupID).Return(tc.response, tc.err)
		expected, err := svc.ViewGroup(context.Background(), tc.token, tc.groupID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, expected, tc.response, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, expected, tc.response))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "CheckAdmin", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("CheckAdmin was not called on %s", tc.desc))
			ok = repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.groupID)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListGroups(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	nGroups := uint64(200)
	parentID := ""
	var aGroups = []groups.Group{}
	for i := uint64(0); i < nGroups; i++ {
		group := groups.Group{
			ID:          testsutil.GenerateUUID(t, idProvider),
			Name:        fmt.Sprintf("Group_%d", i),
			Description: description,
			Metadata: groups.Metadata{
				"field": "value",
			},
			ParentID: parentID,
		}
		parentID = group.ID
		aGroups = append(aGroups, group)
	}

	cases := []struct {
		desc     string
		token    string
		size     uint64
		response groups.GroupsPage
		page     groups.GroupsPage
		err      error
	}{
		{
			desc:  "list all groups",
			token: testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			size:  nGroups,
			err:   nil,
			page: groups.GroupsPage{
				Page: groups.Page{
					Offset: 0,
					Total:  nGroups,
					Limit:  nGroups,
				},
			},
			response: groups.GroupsPage{
				Page: groups.Page{
					Offset: 0,
					Total:  nGroups,
					Limit:  nGroups,
				},
				Groups: aGroups,
			},
		},
		{
			desc:  "list groups with an offset",
			token: testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			size:  150,
			err:   nil,
			page: groups.GroupsPage{
				Page: groups.Page{
					Offset: 50,
					Total:  nGroups,
					Limit:  nGroups,
				},
			},
			response: groups.GroupsPage{
				Page: groups.Page{
					Offset: 0,
					Total:  150,
					Limit:  nGroups,
				},
				Groups: aGroups[50:nGroups],
			},
		},
	}

	for _, tc := range cases {
		repoCall := gRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, tc.err)
		page, err := svc.ListGroups(context.Background(), tc.token, tc.page)
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "RetrieveAll", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("RetrieveAll was not called on %s", tc.desc))
		}
		repoCall.Unset()
	}

}

func TestEnableGroup(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	enabledGroup1 := groups.Group{ID: testsutil.GenerateUUID(t, idProvider), Name: "group1", Status: groups.EnabledStatus}
	disabledGroup := groups.Group{ID: testsutil.GenerateUUID(t, idProvider), Name: "group2", Status: groups.DisabledStatus}
	disabledGroup1 := disabledGroup
	disabledGroup1.Status = groups.EnabledStatus

	casesEnabled := []struct {
		desc     string
		id       string
		token    string
		group    groups.Group
		response groups.Group
		err      error
	}{
		{
			desc:     "enable disabled group",
			id:       disabledGroup.ID,
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			group:    disabledGroup,
			response: disabledGroup1,
			err:      nil,
		},
		{
			desc:     "enable enabled group",
			id:       enabledGroup1.ID,
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			group:    enabledGroup1,
			response: enabledGroup1,
			err:      clients.ErrStatusAlreadyAssigned,
		},
		{
			desc:     "enable non-existing group",
			id:       mocks.WrongID,
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			group:    groups.Group{},
			response: groups.Group{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range casesEnabled {
		repoCall := pRepo.On("CheckAdmin", context.Background(), mock.Anything).Return(nil)
		repoCall1 := gRepo.On("RetrieveByID", context.Background(), tc.id).Return(tc.group, tc.err)
		repoCall2 := gRepo.On("ChangeStatus", context.Background(), tc.id, groups.EnabledStatus).Return(tc.response, tc.err)
		_, err := svc.EnableGroup(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.id)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall2.Parent.AssertCalled(t, "ChangeStatus", context.Background(), tc.id, groups.EnabledStatus)
			assert.True(t, ok, fmt.Sprintf("ChangeStatus was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}

	casesDisabled := []struct {
		desc     string
		status   groups.Status
		size     uint64
		response groups.GroupsPage
	}{
		{
			desc:   "list activated groups",
			status: groups.EnabledStatus,
			size:   2,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  2,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{enabledGroup1, disabledGroup1},
			},
		},
		{
			desc:   "list deactivated groups",
			status: groups.DisabledStatus,
			size:   1,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{disabledGroup},
			},
		},
		{
			desc:   "list activated and deactivated groups",
			status: groups.AllStatus,
			size:   3,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  3,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{enabledGroup1, disabledGroup, disabledGroup1},
			},
		},
	}

	for _, tc := range casesDisabled {
		pm := groups.GroupsPage{
			Page: groups.Page{
				Offset: 0,
				Limit:  100,
				Status: tc.status,
			},
		}
		repoCall := gRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, nil)
		page, err := svc.ListGroups(context.Background(), testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher), pm)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(page.Groups))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))
		repoCall.Unset()
	}
}

func TestDisableGroup(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	enabledGroup1 := groups.Group{ID: testsutil.GenerateUUID(t, idProvider), Name: "group1", Status: groups.EnabledStatus}
	disabledGroup := groups.Group{ID: testsutil.GenerateUUID(t, idProvider), Name: "group2", Status: groups.DisabledStatus}
	disabledGroup1 := enabledGroup1
	disabledGroup1.Status = groups.DisabledStatus

	casesDisabled := []struct {
		desc     string
		id       string
		token    string
		group    groups.Group
		response groups.Group
		err      error
	}{
		{
			desc:     "disable enabled group",
			id:       enabledGroup1.ID,
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			group:    enabledGroup1,
			response: disabledGroup1,
			err:      nil,
		},
		{
			desc:     "disable disabled group",
			id:       disabledGroup.ID,
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			group:    disabledGroup,
			response: groups.Group{},
			err:      clients.ErrStatusAlreadyAssigned,
		},
		{
			desc:     "disable non-existing group",
			id:       mocks.WrongID,
			group:    groups.Group{},
			token:    testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher),
			response: groups.Group{},
			err:      errors.ErrNotFound,
		},
	}

	for _, tc := range casesDisabled {
		repoCall := pRepo.On("CheckAdmin", context.Background(), mock.Anything).Return(nil)
		repoCall1 := gRepo.On("RetrieveByID", context.Background(), tc.id).Return(tc.group, tc.err)
		repoCall2 := gRepo.On("ChangeStatus", context.Background(), tc.id, groups.DisabledStatus).Return(tc.response, tc.err)
		_, err := svc.DisableGroup(context.Background(), tc.token, tc.id)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		if tc.err == nil {
			ok := repoCall1.Parent.AssertCalled(t, "RetrieveByID", context.Background(), tc.id)
			assert.True(t, ok, fmt.Sprintf("RetrieveByID was not called on %s", tc.desc))
			ok = repoCall2.Parent.AssertCalled(t, "ChangeStatus", context.Background(), tc.id, groups.DisabledStatus)
			assert.True(t, ok, fmt.Sprintf("ChangeStatus was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
		repoCall2.Unset()
	}

	casesEnabled := []struct {
		desc     string
		status   groups.Status
		size     uint64
		response groups.GroupsPage
	}{
		{
			desc:   "list activated groups",
			status: groups.EnabledStatus,
			size:   1,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  1,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{enabledGroup1},
			},
		},
		{
			desc:   "list deactivated groups",
			status: groups.DisabledStatus,
			size:   2,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  2,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{disabledGroup1, disabledGroup},
			},
		},
		{
			desc:   "list activated and deactivated groups",
			status: groups.AllStatus,
			size:   3,
			response: groups.GroupsPage{
				Page: groups.Page{
					Total:  3,
					Offset: 0,
					Limit:  100,
				},
				Groups: []groups.Group{enabledGroup1, disabledGroup, disabledGroup1},
			},
		},
	}

	for _, tc := range casesEnabled {
		pm := groups.GroupsPage{
			Page: groups.Page{
				Offset: 0,
				Limit:  100,
				Status: tc.status,
			},
		}
		repoCall := gRepo.On("RetrieveAll", context.Background(), mock.Anything).Return(tc.response, nil)
		page, err := svc.ListGroups(context.Background(), testsutil.GenerateValidToken(t, testsutil.GenerateUUID(t, idProvider), csvc, cRepo, phasher), pm)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(page.Groups))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))
		repoCall.Unset()
	}
}

func TestListMemberships(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	gRepo := new(gmocks.GroupRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)
	e := cmocks.NewEmailer()
	csvc := clients.NewService(cRepo, pRepo, tokenizer, e, phasher, idProvider, passRegex)
	svc := groups.NewService(gRepo, pRepo, tokenizer, idProvider)

	var nGroups = uint64(100)
	var aGroups = []groups.Group{}
	for i := uint64(1); i < nGroups; i++ {
		group := groups.Group{
			Name:     fmt.Sprintf("membership_%d@example.com", i),
			Metadata: groups.Metadata{"role": "group"},
		}
		aGroups = append(aGroups, group)
	}
	validID := testsutil.GenerateUUID(t, idProvider)
	validToken := testsutil.GenerateValidToken(t, validID, csvc, cRepo, phasher)

	cases := []struct {
		desc     string
		token    string
		clientID string
		page     groups.GroupsPage
		response groups.MembershipsPage
		err      error
	}{
		{
			desc:     "list clients with authorized token",
			token:    validToken,
			clientID: testsutil.GenerateUUID(t, idProvider),
			page: groups.GroupsPage{
				Page: groups.Page{
					Action:  "g_list",
					Subject: validID,
				},
			},
			response: groups.MembershipsPage{
				Page: groups.Page{
					Total:  nGroups,
					Offset: 0,
					Limit:  0,
				},
				Memberships: aGroups,
			},
			err: nil,
		},
		{
			desc:     "list clients with offset and limit",
			token:    validToken,
			clientID: testsutil.GenerateUUID(t, idProvider),
			page: groups.GroupsPage{
				Page: groups.Page{
					Offset:  6,
					Total:   nGroups,
					Limit:   nGroups,
					Status:  groups.AllStatus,
					Subject: validID,
					Action:  "g_list",
				},
			},
			response: groups.MembershipsPage{
				Page: groups.Page{
					Total: nGroups - 6,
				},
				Memberships: aGroups[6:nGroups],
			},
		},
		{
			desc:     "list clients with an invalid token",
			token:    inValidToken,
			clientID: testsutil.GenerateUUID(t, idProvider),
			page: groups.GroupsPage{
				Page: groups.Page{
					Action:  "g_list",
					Subject: validID,
				},
			},
			response: groups.MembershipsPage{
				Page: groups.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrAuthentication,
		},
		{
			desc:     "list clients with an invalid id",
			token:    validToken,
			clientID: mocks.WrongID,
			page: groups.GroupsPage{
				Page: groups.Page{
					Action:  "g_list",
					Subject: validID,
				},
			},
			response: groups.MembershipsPage{
				Page: groups.Page{
					Total:  0,
					Offset: 0,
					Limit:  0,
				},
			},
			err: errors.ErrNotFound,
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("CheckAdmin", context.Background(), mock.Anything).Return(nil)
		repoCall1 := gRepo.On("Memberships", context.Background(), tc.clientID, tc.page).Return(tc.response, tc.err)
		page, err := svc.ListMemberships(context.Background(), tc.token, tc.clientID, tc.page)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))
		if tc.err == nil {
			ok := repoCall.Parent.AssertCalled(t, "CheckAdmin", context.Background(), mock.Anything)
			assert.True(t, ok, fmt.Sprintf("CheckAdmin was not called on %s", tc.desc))
			ok = repoCall1.Parent.AssertCalled(t, "Memberships", context.Background(), tc.clientID, tc.page)
			assert.True(t, ok, fmt.Sprintf("Memberships was not called on %s", tc.desc))
		}
		repoCall.Unset()
		repoCall1.Unset()
	}
}
