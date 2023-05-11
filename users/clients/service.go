package clients

import (
	"context"
	"regexp"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/apiutil"
	mfclients "github.com/mainflux/mainflux/pkg/clients"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/users/jwt"
	"github.com/mainflux/mainflux/users/policies"
)

const (
	MyKey             = "mine"
	clientsObjectKey  = "clients"
	updateRelationKey = "c_update"
	listRelationKey   = "c_list"
	deleteRelationKey = "c_delete"
	entityType        = "client"
)

var (
	// ErrMissingResetToken indicates malformed or missing reset token
	// for reseting password.
	ErrMissingResetToken = errors.New("missing reset token")

	// ErrRecoveryToken indicates error in generating password recovery token.
	ErrRecoveryToken = errors.New("failed to generate password recovery token")

	// ErrGetToken indicates error in getting signed token.
	ErrGetToken = errors.New("failed to fetch signed token")

	// ErrPasswordFormat indicates weak password.
	ErrPasswordFormat = errors.New("password does not meet the requirements")
)

// Service unites Clients and Group services.
type Service interface {
	ClientService
	jwt.TokenService
}

type service struct {
	clients    mfclients.Repository
	policies   policies.PolicyRepository
	idProvider mainflux.IDProvider
	hasher     Hasher
	tokens     jwt.TokenRepository
	email      Emailer
	passRegex  *regexp.Regexp
}

// NewService returns a new Clients service implementation.
func NewService(c mfclients.Repository, p policies.PolicyRepository, t jwt.TokenRepository, e Emailer, h Hasher, idp mainflux.IDProvider, pr *regexp.Regexp) Service {
	return service{
		clients:    c,
		policies:   p,
		hasher:     h,
		tokens:     t,
		email:      e,
		idProvider: idp,
		passRegex:  pr,
	}
}

func (svc service) RegisterClient(ctx context.Context, token string, cli mfclients.Client) (mfclients.Client, error) {
	clientID, err := svc.idProvider.ID()
	if err != nil {
		return mfclients.Client{}, err
	}

	// We don't check the error currently since we can register client with empty token
	ownerID, _ := svc.Identify(ctx, token)
	if ownerID != "" && cli.Owner == "" {
		cli.Owner = ownerID
	}
	if cli.Credentials.Secret == "" {
		return mfclients.Client{}, apiutil.ErrMissingSecret
	}
	hash, err := svc.hasher.Hash(cli.Credentials.Secret)
	if err != nil {
		return mfclients.Client{}, errors.Wrap(errors.ErrMalformedEntity, err)
	}
	cli.Credentials.Secret = hash
	if cli.Status != mfclients.DisabledStatus && cli.Status != mfclients.EnabledStatus {
		return mfclients.Client{}, apiutil.ErrInvalidStatus
	}
	if cli.Role != mfclients.UserRole && cli.Role != mfclients.AdminRole {
		return mfclients.Client{}, apiutil.ErrInvalidRole
	}
	cli.ID = clientID
	cli.CreatedAt = time.Now()

	client, err := svc.clients.Save(ctx, cli)
	if err != nil {
		return mfclients.Client{}, err
	}

	return client[0], nil
}

func (svc service) IssueToken(ctx context.Context, identity, secret string) (jwt.Token, error) {
	dbUser, err := svc.clients.RetrieveByIdentity(ctx, identity)
	if err != nil {
		return jwt.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if err := svc.hasher.Compare(secret, dbUser.Credentials.Secret); err != nil {
		return jwt.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	claims := jwt.Claims{
		ClientID: dbUser.ID,
		Email:    dbUser.Credentials.Identity,
	}

	return svc.tokens.Issue(ctx, claims)
}

func (svc service) RefreshToken(ctx context.Context, accessToken string) (jwt.Token, error) {
	claims, err := svc.tokens.Parse(ctx, accessToken)
	if err != nil {
		return jwt.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != jwt.RefreshToken {
		return jwt.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if _, err := svc.clients.RetrieveByID(ctx, claims.ClientID); err != nil {
		return jwt.Token{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	return svc.tokens.Issue(ctx, claims)
}

func (svc service) ViewClient(ctx context.Context, token string, id string) (mfclients.Client, error) {
	ir, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if ir == id {
		return svc.clients.RetrieveByID(ctx, id)
	}

	if err := svc.policies.Evaluate(ctx, entityType, policies.Policy{Subject: ir, Object: id, Actions: []string{listRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}

	return svc.clients.RetrieveByID(ctx, id)
}

func (svc service) ViewProfile(ctx context.Context, token string) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	return svc.clients.RetrieveByID(ctx, id)
}

func (svc service) ListClients(ctx context.Context, token string, pm mfclients.Page) (mfclients.ClientsPage, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.ClientsPage{}, err
	}
	if pm.SharedBy == MyKey {
		pm.SharedBy = id
	}
	if pm.Owner == MyKey {
		pm.Owner = id
	}
	pm.Action = "c_list"
	clients, err := svc.clients.RetrieveAll(ctx, pm)
	if err != nil {
		return mfclients.ClientsPage{}, err
	}
	for i, client := range clients.Clients {
		if client.ID == id {
			clients.Clients = append(clients.Clients[:i], clients.Clients[i+1:]...)
			if clients.Total != 0 {
				clients.Total = clients.Total - 1
			}
		}
	}

	return clients, nil
}

func (svc service) UpdateClient(ctx context.Context, token string, cli mfclients.Client) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: cli.ID, Actions: []string{updateRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}

	client := mfclients.Client{
		ID:        cli.ID,
		Name:      cli.Name,
		Metadata:  cli.Metadata,
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}

	return svc.clients.Update(ctx, client)
}

func (svc service) UpdateClientTags(ctx context.Context, token string, cli mfclients.Client) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: cli.ID, Actions: []string{updateRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}

	client := mfclients.Client{
		ID:        cli.ID,
		Tags:      cli.Tags,
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}

	return svc.clients.UpdateTags(ctx, client)
}

func (svc service) UpdateClientIdentity(ctx context.Context, token, clientID, identity string) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: clientID, Actions: []string{updateRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}

	cli := mfclients.Client{
		ID: id,
		Credentials: mfclients.Credentials{
			Identity: identity,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}
	return svc.clients.UpdateIdentity(ctx, cli)
}

func (svc service) GenerateResetToken(ctx context.Context, email, host string) error {
	client, err := svc.clients.RetrieveByIdentity(ctx, email)
	if err != nil || client.Credentials.Identity == "" {
		return errors.ErrNotFound
	}
	t, err := svc.IssueToken(ctx, client.Credentials.Identity, client.Credentials.Secret)
	if err != nil {
		return errors.Wrap(ErrRecoveryToken, err)
	}
	return svc.SendPasswordReset(ctx, host, email, t.AccessToken)
}

func (svc service) ResetSecret(ctx context.Context, resetToken, secret string) error {
	id, err := svc.Identify(ctx, resetToken)
	if err != nil {
		return errors.Wrap(errors.ErrAuthentication, err)
	}
	c, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return err
	}
	if c.Credentials.Identity == "" {
		return errors.ErrNotFound
	}
	if !svc.passRegex.MatchString(secret) {
		return ErrPasswordFormat
	}
	secret, err = svc.hasher.Hash(secret)
	if err != nil {
		return err
	}
	c = mfclients.Client{
		Credentials: mfclients.Credentials{
			Identity: c.Credentials.Identity,
			Secret:   secret,
		},
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}
	if _, err := svc.clients.UpdateSecret(ctx, c); err != nil {
		return err
	}
	return nil
}

func (svc service) UpdateClientSecret(ctx context.Context, token, oldSecret, newSecret string) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if !svc.passRegex.MatchString(newSecret) {
		return mfclients.Client{}, ErrPasswordFormat
	}
	dbClient, err := svc.clients.RetrieveByID(ctx, id)
	if err != nil {
		return mfclients.Client{}, err
	}
	if _, err := svc.IssueToken(ctx, dbClient.Credentials.Identity, oldSecret); err != nil {
		return mfclients.Client{}, errors.ErrAuthentication
	}
	newSecret, err = svc.hasher.Hash(newSecret)
	if err != nil {
		return mfclients.Client{}, err
	}
	dbClient.Credentials.Secret = newSecret
	dbClient.UpdatedAt = time.Now()
	dbClient.UpdatedBy = id

	return svc.clients.UpdateSecret(ctx, dbClient)
}

func (svc service) SendPasswordReset(_ context.Context, host, email, token string) error {
	to := []string{email}
	return svc.email.SendPasswordReset(to, host, token)
}

func (svc service) UpdateClientOwner(ctx context.Context, token string, cli mfclients.Client) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: cli.ID, Actions: []string{updateRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}

	client := mfclients.Client{
		ID:        cli.ID,
		Owner:     cli.Owner,
		UpdatedAt: time.Now(),
		UpdatedBy: id,
	}

	return svc.clients.UpdateOwner(ctx, client)
}

func (svc service) EnableClient(ctx context.Context, token, id string) (mfclients.Client, error) {
	client := mfclients.Client{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mfclients.EnabledStatus,
	}
	client, err := svc.changeClientStatus(ctx, token, client)
	if err != nil {
		return mfclients.Client{}, errors.Wrap(mfclients.ErrEnableClient, err)
	}

	return client, nil
}

func (svc service) DisableClient(ctx context.Context, token, id string) (mfclients.Client, error) {
	client := mfclients.Client{
		ID:        id,
		UpdatedAt: time.Now(),
		Status:    mfclients.DisabledStatus,
	}
	client, err := svc.changeClientStatus(ctx, token, client)
	if err != nil {
		return mfclients.Client{}, errors.Wrap(mfclients.ErrDisableClient, err)
	}

	return client, nil
}

func (svc service) ListMembers(ctx context.Context, token, groupID string, pm mfclients.Page) (mfclients.MembersPage, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.MembersPage{}, err
	}
	// If the user is admin, fetch all members from the database.
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: clientsObjectKey, Actions: []string{listRelationKey}}); err == nil {
		return svc.clients.Members(ctx, groupID, pm)
	}
	pm.Subject = id
	pm.Action = "g_list"

	return svc.clients.Members(ctx, groupID, pm)
}

func (svc service) changeClientStatus(ctx context.Context, token string, client mfclients.Client) (mfclients.Client, error) {
	id, err := svc.Identify(ctx, token)
	if err != nil {
		return mfclients.Client{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: client.ID, Actions: []string{deleteRelationKey}}); err != nil {
		return mfclients.Client{}, err
	}
	dbClient, err := svc.clients.RetrieveByID(ctx, client.ID)
	if err != nil {
		return mfclients.Client{}, err
	}
	if dbClient.Status == client.Status {
		return mfclients.Client{}, mfclients.ErrStatusAlreadyAssigned
	}
	client.UpdatedBy = id
	return svc.clients.ChangeStatus(ctx, client)
}

func (svc service) authorizeByID(ctx context.Context, entityType string, p policies.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.policies.CheckAdmin(ctx, p.Subject); err == nil {
		return nil
	}
	return svc.policies.Evaluate(ctx, entityType, p)
}

func (svc service) Identify(ctx context.Context, tkn string) (string, error) {
	claims, err := svc.tokens.Parse(ctx, tkn)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != jwt.AccessToken {
		return "", errors.ErrAuthentication
	}

	return claims.ClientID, nil
}
