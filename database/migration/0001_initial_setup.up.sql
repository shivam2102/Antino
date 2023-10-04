CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS token_info
(
    id           TEXT PRIMARY KEY         DEFAULT uuid_generate_v1()::TEXT,
    invite_token text                     not null,
    archived_at  TIMESTAMP WITH TIME ZONE not null,
    created_at   TIMESTAMP WITH TIME ZONE default now()
);

CREATE TABLE IF NOT EXISTS users
(
    id          TEXT PRIMARY KEY         DEFAULT uuid_generate_v1()::TEXT,
    password    TEXT not null,
    email       text not null,
    name        text not null,
    archived_at TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE default now()
);
