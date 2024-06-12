// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/absmach/magistrala/internal/postgres"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	pgclients "github.com/absmach/magistrala/pkg/clients/postgres"
	"github.com/absmach/magistrala/pkg/errors"
	repoerr "github.com/absmach/magistrala/pkg/errors/repository"
)

var _ mgclients.Repository = (*clientRepo)(nil)

type clientRepo struct {
	pgclients.Repository
}

// Repository defines the required dependencies for Client repository.
//
//go:generate mockery --name Repository --output=../mocks --filename repository.go --quiet --note "Copyright (c) Abstract Machines"
type Repository interface {
	mgclients.Repository

	// Save persists the client account. A non-nil error is returned to indicate
	// operation failure.
	Save(ctx context.Context, client mgclients.Client) (mgclients.Client, errors.Error)

	RetrieveByID(ctx context.Context, id string) (mgclients.Client, errors.Error)

	UpdateRole(ctx context.Context, client mgclients.Client) (mgclients.Client, errors.Error)

	CheckSuperAdmin(ctx context.Context, adminID string) errors.Error
}

// NewRepository instantiates a PostgreSQL
// implementation of Clients repository.
func NewRepository(db postgres.Database) Repository {
	return &clientRepo{
		Repository: pgclients.Repository{DB: db},
	}
}

func (repo clientRepo) Save(ctx context.Context, c mgclients.Client) (mgclients.Client, errors.Error) {
	q := `INSERT INTO clients (id, name, tags, identity, secret, metadata, created_at, status, role)
        VALUES (:id, :name, :tags, :identity, :secret, :metadata, :created_at, :status, :role)
        RETURNING id, name, tags, identity, metadata, status, created_at`
	dbc, err := pgclients.ToDBClient(c)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrCreateEntity, err)
	}

	row, Err := repo.DB.NamedQueryContext(ctx, q, dbc)
	if Err != nil {
		return mgclients.Client{}, errors.Cast(postgres.HandleError(repoerr.ErrCreateEntity, Err))
	}

	defer row.Close()
	row.Next()
	dbc = pgclients.DBClient{}
	if err := row.StructScan(&dbc); err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrFailedOpDB, err)
	}

	client, err := pgclients.ToClient(dbc)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrFailedOpDB, err)
	}

	return client, nil
}

func (repo clientRepo) CheckSuperAdmin(ctx context.Context, adminID string) errors.Error {
	q := "SELECT 1 FROM clients WHERE id = $1 AND role = $2"
	rows, err := repo.DB.QueryContext(ctx, q, adminID, mgclients.AdminRole)
	if err != nil {
		return errors.Cast(postgres.HandleError(repoerr.ErrViewEntity, err))
	}
	defer rows.Close()

	if rows.Next() {
		if err := rows.Err(); err != nil {
			return errors.Cast(postgres.HandleError(repoerr.ErrViewEntity, err))
		}
		return nil
	}

	return repoerr.ErrNotFound
}

func (repo clientRepo) RetrieveByID(ctx context.Context, id string) (mgclients.Client, errors.Error) {
	q := `SELECT id, name, tags, identity, secret, metadata, created_at, updated_at, updated_by, status, role
        FROM clients WHERE id = :id`

	dbc := pgclients.DBClient{
		ID: id,
	}

	rows, err := repo.DB.NamedQueryContext(ctx, q, dbc)
	if err != nil {
		return mgclients.Client{}, errors.Cast(postgres.HandleError(repoerr.ErrViewEntity, err))
	}
	defer rows.Close()

	dbc = pgclients.DBClient{}
	if rows.Next() {
		if err = rows.StructScan(&dbc); err != nil {
			return mgclients.Client{}, errors.Cast(postgres.HandleError(repoerr.ErrViewEntity, err))
		}

		client, err := pgclients.ToClient(dbc)
		if err != nil {
			return mgclients.Client{}, errors.Wrap(repoerr.ErrFailedOpDB, err)
		}

		return client, nil
	}

	return mgclients.Client{}, repoerr.ErrNotFound
}

func (repo clientRepo) RetrieveAll(ctx context.Context, pm mgclients.Page) (mgclients.ClientsPage, errors.Error) {
	query, err := pgclients.PageQuery(pm)
	if err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrViewEntity, err)
	}

	q := fmt.Sprintf(`SELECT c.id, c.name, c.tags, c.identity, c.metadata,  c.status, c.role,
					c.created_at, c.updated_at, COALESCE(c.updated_by, '') AS updated_by FROM clients c %s ORDER BY c.created_at LIMIT :limit OFFSET :offset;`, query)

	dbPage, err := pgclients.ToDBClientsPage(pm)
	if err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	rows, Err := repo.DB.NamedQueryContext(ctx, q, dbPage)
	if Err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, Err)
	}
	defer rows.Close()

	var items []mgclients.Client
	for rows.Next() {
		dbc := pgclients.DBClient{}
		if err := rows.StructScan(&dbc); err != nil {
			return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrViewEntity, err)
		}

		c, err := pgclients.ToClient(dbc)
		if err != nil {
			return mgclients.ClientsPage{}, errors.Cast(err)
		}

		items = append(items, c)
	}
	cq := fmt.Sprintf(`SELECT COUNT(*) FROM clients c %s;`, query)

	total, Err := postgres.Total(ctx, repo.DB, cq, dbPage)
	if Err != nil {
		return mgclients.ClientsPage{}, errors.Wrap(repoerr.ErrViewEntity, Err)
	}

	page := mgclients.ClientsPage{
		Clients: items,
		Page: mgclients.Page{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
		},
	}

	return page, nil
}

func (repo clientRepo) UpdateRole(ctx context.Context, client mgclients.Client) (mgclients.Client, errors.Error) {
	query := `UPDATE clients SET role = :role, updated_at = :updated_at, updated_by = :updated_by
        WHERE id = :id AND status = :status
        RETURNING id, name, tags, identity, metadata, status, role, created_at, updated_at, updated_by`

	dbc, err := pgclients.ToDBClient(client)
	if err != nil {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	row, Err := repo.DB.NamedQueryContext(ctx, query, dbc)
	if Err != nil {
		return mgclients.Client{}, errors.Cast(postgres.HandleError(Err, repoerr.ErrUpdateEntity))
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return mgclients.Client{}, errors.Wrap(repoerr.ErrNotFound, row.Err())
	}
	dbc = pgclients.DBClient{}
	if err := row.StructScan(&dbc); err != nil {
		return mgclients.Client{}, errors.Cast(err)
	}

	cl, err := pgclients.ToClient(dbc)
	return cl, errors.Cast(err)
}
