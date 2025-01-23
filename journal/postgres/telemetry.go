// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/absmach/supermq/journal"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/absmach/supermq/pkg/postgres"
	"github.com/jackc/pgtype"
)

func (repo *repository) SaveClientTelemetry(ctx context.Context, ct journal.ClientTelemetry) error {
	q := `INSERT INTO clients_telemetry (client_id, domain_id, inbound_messages, outbound_messages, subscriptions, first_seen, last_seen)
		VALUES (:client_id, :domain_id, :inbound_messages, :outbound_messages, :subscriptions, :first_seen, :last_seen);`

	dbct, err := toDBClientsTelemetry(ct)
	if err != nil {
		return errors.Wrap(repoerr.ErrCreateEntity, err)
	}

	if _, err := repo.db.NamedExecContext(ctx, q, dbct); err != nil {
		return postgres.HandleError(repoerr.ErrCreateEntity, err)
	}

	return nil
}

func (repo *repository) DeleteClientTelemetry(ctx context.Context, clientID, domainID string) error {
	q := "DELETE FROM clients_telemetry AS ct WHERE ct.client_id = :client_id AND ct.domain_id = :domain_id;"

	dbct := dbClientTelemetry{
		ClientID: clientID,
		DomainID: domainID,
	}

	result, err := repo.db.NamedExecContext(ctx, q, dbct)
	if err != nil {
		return postgres.HandleError(repoerr.ErrRemoveEntity, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return repoerr.ErrNotFound
	}
	return nil
}

func (repo *repository) RetrieveClientTelemetry(ctx context.Context, clientID, domainID string) (journal.ClientTelemetry, error) {
	q := "SELECT * FROM clients_telemetry WHERE client_id = :client_id AND domain_id = :domain_id;"

	dbct := dbClientTelemetry{
		ClientID: clientID,
		DomainID: domainID,
	}

	rows, err := repo.db.NamedQueryContext(ctx, q, dbct)
	if err != nil {
		return journal.ClientTelemetry{}, postgres.HandleError(repoerr.ErrViewEntity, err)
	}
	defer rows.Close()

	dbct = dbClientTelemetry{}
	if rows.Next() {
		if err = rows.StructScan(&dbct); err != nil {
			return journal.ClientTelemetry{}, postgres.HandleError(repoerr.ErrViewEntity, err)
		}

		ct, err := toClientsTelemetry(dbct)
		if err != nil {
			return journal.ClientTelemetry{}, errors.Wrap(repoerr.ErrFailedOpDB, err)
		}

		return ct, nil
	}

	return journal.ClientTelemetry{}, repoerr.ErrNotFound
}

func (repo *repository) AddSubscription(ctx context.Context, clientID, sub string) error {
	q := `
		UPDATE clients_telemetry
		SET subscriptions = ARRAY_APPEND(subscriptions, :subscriptions),
			last_seen = :last_seen
		WHERE client_id = :client_id;
	`
	ct := journal.ClientTelemetry{
		ClientID:      clientID,
		Subscriptions: []string{sub},
		LastSeen:      time.Now(),
	}
	dbct, err := toDBClientsTelemetry(ct)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	result, err := repo.db.NamedExecContext(ctx, q, dbct)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return repoerr.ErrNotFound
	}

	return nil
}

func (repo *repository) RemoveSubscription(ctx context.Context, clientID, sub string) error {
	q := `
		UPDATE clients_telemetry
		SET subscriptions = ARRAY_REMOVE(subscriptions, :subscriptions)
		WHERE client_id = :client_id
		AND (:subscriptions = ANY(subscriptions))
	`
	ct := journal.ClientTelemetry{
		ClientID:      clientID,
		Subscriptions: []string{sub},
	}
	dbct, err := toDBClientsTelemetry(ct)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	result, err := repo.db.NamedExecContext(ctx, q, dbct)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return repoerr.ErrNotFound
	}

	return nil
}

func (repo *repository) RemoveSubscriptionWithConnID(ctx context.Context, connID, clientID string) error {
	q := `
		UPDATE clients_telemetry
		SET subscriptions = ARRAY(
			SELECT sub
			FROM unnest(subscriptions) AS sub
			WHERE sub NOT LIKE '%' || $1 || '%'
		)
		WHERE client_id = $2;
	`
	_, err := repo.db.ExecContext(ctx, q, connID, clientID)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	return nil
}

func (repo *repository) IncrementInboundMessages(ctx context.Context, clientID string) error {
	q := `
		UPDATE clients_telemetry
		SET inbound_messages = inbound_messages + 1,
			last_seen = :last_seen
		WHERE client_id = :client_id;
	`

	ct := journal.ClientTelemetry{
		ClientID: clientID,
		LastSeen: time.Now(),
	}
	dbct, err := toDBClientsTelemetry(ct)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	result, err := repo.db.NamedExecContext(ctx, q, dbct)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return repoerr.ErrNotFound
	}

	return nil
}

func (repo *repository) IncrementOutboundMessages(ctx context.Context, channelID, subtopic string) error {
	q := `
		WITH matched_clients AS (
			SELECT 
				client_id,
				domain_id,
				COUNT(*) AS match_count
			FROM 
				clients_telemetry,
				unnest(subscriptions) AS sub
			WHERE 
				sub LIKE '%' || $1 || ':' || $2 || '%'
			GROUP BY 
				client_id, domain_id
		)
		UPDATE clients_telemetry
		SET outbound_messages = outbound_messages + matched_clients.match_count
		FROM matched_clients
		WHERE clients_telemetry.client_id = matched_clients.client_id
		AND clients_telemetry.domain_id = matched_clients.domain_id;
	`

	_, err := repo.db.ExecContext(ctx, q, channelID, subtopic)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	return nil
}

type dbClientTelemetry struct {
	ClientID         string           `db:"client_id"`
	DomainID         string           `db:"domain_id"`
	Subscriptions    pgtype.TextArray `db:"subscriptions"`
	InboundMessages  uint64           `db:"inbound_messages"`
	OutboundMessages uint64           `db:"outbound_messages"`
	FirstSeen        time.Time        `db:"first_seen"`
	LastSeen         sql.NullTime     `db:"last_seen"`
}

func toDBClientsTelemetry(ct journal.ClientTelemetry) (dbClientTelemetry, error) {
	var subs pgtype.TextArray
	if err := subs.Set(ct.Subscriptions); err != nil {
		return dbClientTelemetry{}, err
	}

	var lastSeen sql.NullTime
	if ct.LastSeen != (time.Time{}) {
		lastSeen = sql.NullTime{Time: ct.LastSeen, Valid: true}
	}

	return dbClientTelemetry{
		ClientID:         ct.ClientID,
		DomainID:         ct.DomainID,
		Subscriptions:    subs,
		InboundMessages:  ct.InboundMessages,
		OutboundMessages: ct.OutboundMessages,
		FirstSeen:        ct.FirstSeen,
		LastSeen:         lastSeen,
	}, nil
}

func toClientsTelemetry(dbct dbClientTelemetry) (journal.ClientTelemetry, error) {
	var subs []string
	for _, e := range dbct.Subscriptions.Elements {
		subs = append(subs, e.String)
	}

	var lastSeen time.Time
	if dbct.LastSeen.Valid {
		lastSeen = dbct.LastSeen.Time
	}

	return journal.ClientTelemetry{
		ClientID:         dbct.ClientID,
		DomainID:         dbct.DomainID,
		Subscriptions:    subs,
		InboundMessages:  dbct.InboundMessages,
		OutboundMessages: dbct.OutboundMessages,
		FirstSeen:        dbct.FirstSeen,
		LastSeen:         lastSeen,
	}, nil
}
