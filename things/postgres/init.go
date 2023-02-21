package postgres

import (
	_ "github.com/jackc/pgx/v5/stdlib" // required for SQL access
	migrate "github.com/rubenv/sql-migrate"
)

func Migration() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "clients_01",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS clients (
						id			VARCHAR(254) PRIMARY KEY,
						name		VARCHAR(1024),
						owner_id	VARCHAR(254),
						identity	VARCHAR(254),
						secret		VARCHAR(4096) UNIQUE NOT NULL,
						tags		TEXT[],
						metadata	JSONB,
						created_at	TIMESTAMP,
						updated_at	TIMESTAMP,
						status		SMALLINT NOT NULL CHECK (status >= 0) DEFAULT 1,
						UNIQUE		(owner_id, secret)
					)`,
					`CREATE TABLE IF NOT EXISTS groups (
						id			VARCHAR(254) PRIMARY KEY,
						parent_id	VARCHAR(254),
						owner_id	VARCHAR(254) NOT NULL,
						name		VARCHAR(1024) NOT NULL,
						description	VARCHAR(1024),
						metadata	JSONB,
						created_at	TIMESTAMP,
						updated_at	TIMESTAMP,
						status		SMALLINT NOT NULL CHECK (status >= 0) DEFAULT 1,
						UNIQUE		(owner_id, name),
						FOREIGN KEY	(parent_id) REFERENCES groups (id) ON DELETE CASCADE
					)`,
					`CREATE TABLE IF NOT EXISTS policies (
						owner_id	VARCHAR(254) NOT NULL,
						subject		VARCHAR(254) NOT NULL,
						object		VARCHAR(254) NOT NULL,
						actions		TEXT[] NOT NULL,
						created_at	TIMESTAMP,
						updated_at	TIMESTAMP,
						FOREIGN KEY	(object) REFERENCES groups (id) ON DELETE CASCADE ON UPDATE CASCADE
					)`,
				},
				Down: []string{
					`DROP TABLE IF EXISTS clients`,
					`DROP TABLE IF EXISTS groups`,
					`DROP TABLE IF EXISTS policies`,
				},
			},
		},
	}
}
