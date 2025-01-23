// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	_ "github.com/jackc/pgx/v5/stdlib" // required for SQL access
	migrate "github.com/rubenv/sql-migrate"
)

func Migration() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "journal_01",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS journal (
						id          VARCHAR(36) PRIMARY KEY,
						operation	VARCHAR NOT NULL,
						domain		VARCHAR,
						occurred_at	TIMESTAMP NOT NULL,
						attributes	JSONB NOT NULL,
						metadata	JSONB,
						UNIQUE(operation, occurred_at, attributes)
					)`,
					`CREATE INDEX idx_journal_default_user_filter ON journal(operation, (attributes->>'id'), (attributes->>'user_id'), occurred_at DESC);`,
					`CREATE INDEX idx_journal_default_group_filter ON journal(operation, (attributes->>'id'), (attributes->>'group_id'), occurred_at DESC);`,
					`CREATE INDEX idx_journal_default_client_filter ON journal(operation, (attributes->>'id'), (attributes->>'client_id'), occurred_at DESC);`,
					`CREATE INDEX idx_journal_default_channel_filter ON journal(operation, (attributes->>'id'), (attributes->>'channel_id'), occurred_at DESC);`,
					`CREATE TABLE IF NOT EXISTS clients_telemetry (
						client_id         VARCHAR(36) NOT NULL,
						domain_id         VARCHAR(36) NOT NULL,
						subscriptions     TEXT[] DEFAULT '{}',
						inbound_messages  BIGINT DEFAULT 0,
						outbound_messages BIGINT DEFAULT 0,
						first_seen        TIMESTAMP,
						last_seen         TIMESTAMP,
						PRIMARY KEY (client_id, domain_id)
					)`,
					`CREATE INDEX idx_subscriptions_gin ON clients_telemetry USING GIN (subscriptions);`,
				},
				Down: []string{
					`DROP TABLE IF EXISTS clients_telemetry`,
					`DROP TABLE IF EXISTS journal`,
				},
			},
		},
	}
}
