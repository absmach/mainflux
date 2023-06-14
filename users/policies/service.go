package policies

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/apiutil"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/users/jwt"
)

// Possible token types are access and refresh tokens.
const (
	AccessToken = "access"
)

// Service unites Clients and Group services.
type Service interface {
	PolicyService
}

type service struct {
	policies   PolicyRepository
	idProvider mainflux.IDProvider
	tokens     jwt.TokenRepository
}

// NewService returns a new Clients service implementation.
func NewService(p PolicyRepository, t jwt.TokenRepository, idp mainflux.IDProvider) Service {
	return service{
		policies:   p,
		tokens:     t,
		idProvider: idp,
	}
}

func (svc service) Authorize(ctx context.Context, entityType string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.policies.CheckAdmin(ctx, p.Subject); err == nil {
		return nil
	}

	return svc.policies.Evaluate(ctx, entityType, p)
}

func (svc service) UpdatePolicy(ctx context.Context, token string, p Policy) error {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, id, p); err != nil {
		return err
	}
	p.UpdatedAt = time.Now()
	p.UpdatedBy = id

	return svc.policies.Update(ctx, p)
}

func (svc service) AddPolicy(ctx context.Context, token string, p Policy) error {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}

	pm := Page{Subject: p.Subject, Object: p.Object, Offset: 0, Limit: 1}
	page, err := svc.policies.Retrieve(ctx, pm)
	if err != nil {
		return err
	}

	// If the policy already exists, replace the actions
	if len(page.Policies) == 1 {
		p.UpdatedAt = time.Now()
		p.UpdatedBy = id
		return svc.policies.Update(ctx, p)
	}

	if err := svc.checkActionRank(ctx, id, p); err != nil {
		return err
	}
	p.OwnerID = id
	p.CreatedAt = time.Now()

	return svc.policies.Save(ctx, p)
}

func (svc service) DeletePolicy(ctx context.Context, token string, p Policy) error {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return err
	}
	if err := svc.checkActionRank(ctx, id, p); err != nil {
		return err
	}

	return svc.policies.Delete(ctx, p)
}

func (svc service) ListPolicy(ctx context.Context, token string, pm Page) (PolicyPage, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return PolicyPage{}, err
	}
	if err := pm.Validate(); err != nil {
		return PolicyPage{}, err
	}
	// If the user is admin, return all policies
	if err := svc.policies.CheckAdmin(ctx, id); err == nil {
		return svc.policies.Retrieve(ctx, pm)
	}

	// If the user is not admin, return only the policies that they are in
	pm.Subject = id
	pm.Object = id

	return svc.policies.Retrieve(ctx, pm)
}

// checkActionRank check if an action is in the provide list of actions
func (svc service) checkActionRank(ctx context.Context, clientID string, p Policy) error {
	page, err := svc.policies.Retrieve(ctx, Page{Subject: clientID, Object: p.Object})
	if err != nil {
		return err
	}
	if len(page.Policies) != 0 {
		for _, a := range p.Actions {
			var found = false
			for _, v := range page.Policies[0].Actions {
				if v == a {
					found = true
					break
				}
			}
			if !found {
				return apiutil.ErrHigherPolicyRank
			}
		}
	}

	return nil

}

func (svc service) identify(ctx context.Context, tkn string) (string, error) {
	claims, err := svc.tokens.Parse(ctx, tkn)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != AccessToken {
		return "", errors.ErrAuthentication
	}

	return claims.ClientID, nil
}
