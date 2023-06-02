package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgtype"
	"github.com/mainflux/mainflux/internal/postgres"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/things/policies"
)

var _ policies.Repository = (*prepo)(nil)

var (
	// ErrInvalidEntityType indicates that the entity type is invalid.
	ErrInvalidEntityType = errors.New("invalid entity type")
)

type prepo struct {
	db postgres.Database
}

// NewRepository instantiates a PostgreSQL implementation of policy repository.
func NewRepository(db postgres.Database) policies.Repository {
	return &prepo{
		db: db,
	}
}

func (pr prepo) Save(ctx context.Context, policy policies.Policy) (policies.Policy, error) {
	q := `INSERT INTO policies (owner_id, subject, object, actions, created_at, updated_at, updated_by)
		VALUES (:owner_id, :subject, :object, :actions, :created_at, :updated_at, :updated_by)
		RETURNING owner_id, subject, object, actions, created_at, updated_at, updated_by;`

	dbp, err := toDBPolicy(policy)
	if err != nil {
		return policies.Policy{}, errors.Wrap(errors.ErrCreateEntity, err)
	}

	row, err := pr.db.NamedQueryContext(ctx, q, dbp)
	if err != nil {
		return policies.Policy{}, postgres.HandleError(err, errors.ErrCreateEntity)
	}

	defer row.Close()
	row.Next()
	dbp = dbPolicy{}
	if err := row.StructScan(&dbp); err != nil {
		return policies.Policy{}, err
	}

	return toPolicy(dbp)
}

func (pr prepo) RetrieveOne(ctx context.Context, subject, object string) (policies.Policy, error) {
	q := `SELECT subject, object, actions 
			FROM policies p INNER JOIN clients c ON c.id = p.subject
			WHERE c.secret = :subject AND p.object = :object`
	params := struct {
		Subject string `db:"subject"`
		Object  string `db:"object"`
	}{
		Subject: subject,
		Object:  object,
	}
	row, err := pr.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return policies.Policy{}, postgres.HandleError(err, errors.ErrAuthorization)
	}

	defer row.Close()

	if ok := row.Next(); !ok {
		return policies.Policy{}, errors.Wrap(errors.ErrAuthorization, row.Err())
	}
	var p dbPolicy
	if err := row.StructScan(&p); err != nil {
		return policies.Policy{}, err
	}
	return toPolicy(p)
}

func (pr prepo) Evaluate(ctx context.Context, entityType string, policy policies.Policy) error {
	q := ""
	switch entityType {
	case "client":
		// Evaluates if two clients are connected to the same group and the subject has the specified action
		// or subject is the owner of the object
		q = fmt.Sprintf(`SELECT COALESCE(p.subject, c.id) as subject FROM policies p
		JOIN policies p2 ON p.object = p2.object LEFT JOIN clients c ON c.owner_id = :subject AND c.id = :object
		WHERE (p.subject = :subject AND p2.subject = :object AND '%s' = ANY(p.actions)) OR (c.id IS NOT NULL) LIMIT 1;`,
			policy.Actions[0])
	case "group":
		// Evaluates if client is connected to the specified group and has the required action
		q = fmt.Sprintf(`SELECT DISTINCT policies.subject FROM policies
		LEFT JOIN groups ON groups.owner_id = policies.subject AND groups.id = policies.object
		WHERE policies.subject = :subject AND policies.object = :object AND '%s' = ANY(policies.actions)
		LIMIT 1`, policy.Actions[0])
	default:
		return ErrInvalidEntityType
	}
	dbu, err := toDBPolicy(policy)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	row, err := pr.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return postgres.HandleError(err, errors.ErrAuthorization)
	}

	defer row.Close()

	if ok := row.Next(); !ok {
		return errors.Wrap(errors.ErrAuthorization, row.Err())
	}
	var rPolicy dbPolicy
	if err := row.StructScan(&rPolicy); err != nil {
		return err
	}
	return nil
}

func (pr prepo) Update(ctx context.Context, policy policies.Policy) (policies.Policy, error) {
	q := `UPDATE policies SET actions = :actions, updated_at = :updated_at, updated_by = :updated_by
		WHERE subject = :subject AND object = :object
		RETURNING owner_id, subject, object, actions, created_at, updated_at;`

	dbp, err := toDBPolicy(policy)
	if err != nil {
		return policies.Policy{}, errors.Wrap(errors.ErrUpdateEntity, err)
	}

	row, err := pr.db.NamedQueryContext(ctx, q, dbp)
	if err != nil {
		return policies.Policy{}, postgres.HandleError(err, errors.ErrUpdateEntity)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return policies.Policy{}, errors.Wrap(errors.ErrNotFound, row.Err())
	}
	dbp = dbPolicy{}
	if err := row.StructScan(&dbp); err != nil {
		return policies.Policy{}, errors.Wrap(err, errors.ErrUpdateEntity)
	}
	return toPolicy(dbp)
}

func (pr prepo) Retrieve(ctx context.Context, pm policies.Page) (policies.PolicyPage, error) {
	var query []string
	var emq string

	if pm.OwnerID != "" {
		query = append(query, "owner_id = :owner_id")
	}
	if pm.Subject != "" {
		query = append(query, "subject = :subject")
	}
	if pm.Object != "" {
		query = append(query, "object = :object")
	}
	if pm.Action != "" {
		query = append(query, ":action = ANY (actions)")
	}

	if len(query) > 0 {
		emq = fmt.Sprintf(" WHERE %s", strings.Join(query, " AND "))
	}

	q := fmt.Sprintf(`SELECT owner_id, subject, object, actions
		FROM policies %s ORDER BY updated_at LIMIT :limit OFFSET :offset;`, emq)

	dbPage, err := toDBPoliciesPage(pm)
	if err != nil {
		return policies.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	rows, err := pr.db.NamedQueryContext(ctx, q, dbPage)
	if err != nil {
		return policies.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	defer rows.Close()

	var items []policies.Policy
	for rows.Next() {
		dbp := dbPolicy{}
		if err := rows.StructScan(&dbp); err != nil {
			return policies.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
		}

		policy, err := toPolicy(dbp)
		if err != nil {
			return policies.PolicyPage{}, err
		}

		items = append(items, policy)
	}

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM policies %s;`, emq)

	total, err := postgres.Total(ctx, pr.db, cq, dbPage)
	if err != nil {
		return policies.PolicyPage{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	page := policies.PolicyPage{
		Policies: items,
		Page: policies.Page{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
		},
	}

	return page, nil
}

func (pr prepo) Delete(ctx context.Context, p policies.Policy) error {
	dbp := dbPolicy{
		Subject: p.Subject,
		Object:  p.Object,
	}
	q := `DELETE FROM policies WHERE subject = :subject AND object = :object`
	if _, err := pr.db.NamedExecContext(ctx, q, dbp); err != nil {
		return errors.Wrap(errors.ErrRemoveEntity, err)
	}
	return nil
}

type dbPolicy struct {
	OwnerID   string           `db:"owner_id"`
	Subject   string           `db:"subject"`
	Object    string           `db:"object"`
	Actions   pgtype.TextArray `db:"actions"`
	CreatedAt time.Time        `db:"created_at"`
	UpdatedAt time.Time        `db:"updated_at"`
	UpdatedBy string           `db:"updated_by"`
}

func toDBPolicy(p policies.Policy) (dbPolicy, error) {
	var ps pgtype.TextArray
	if err := ps.Set(p.Actions); err != nil {
		return dbPolicy{}, err
	}

	return dbPolicy{
		OwnerID:   p.OwnerID,
		Subject:   p.Subject,
		Object:    p.Object,
		Actions:   ps,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
		UpdatedBy: p.UpdatedBy,
	}, nil
}

func toPolicy(dbp dbPolicy) (policies.Policy, error) {
	var ps []string
	for _, e := range dbp.Actions.Elements {
		ps = append(ps, e.String)
	}

	return policies.Policy{
		OwnerID:   dbp.OwnerID,
		Subject:   dbp.Subject,
		Object:    dbp.Object,
		Actions:   ps,
		CreatedAt: dbp.CreatedAt,
		UpdatedAt: dbp.UpdatedAt,
		UpdatedBy: dbp.UpdatedBy,
	}, nil
}

func toDBPoliciesPage(pm policies.Page) (dbPoliciesPage, error) {
	return dbPoliciesPage{
		Total:   pm.Total,
		Offset:  pm.Offset,
		Limit:   pm.Limit,
		OwnerID: pm.OwnerID,
		Subject: pm.Subject,
		Object:  pm.Object,
		Action:  pm.Action,
	}, nil
}

type dbPoliciesPage struct {
	Total   uint64 `db:"total"`
	Limit   uint64 `db:"limit"`
	Offset  uint64 `db:"offset"`
	OwnerID string `db:"owner_id"`
	Subject string `db:"subject"`
	Object  string `db:"object"`
	Action  string `db:"action"`
}
