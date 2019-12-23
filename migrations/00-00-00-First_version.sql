-- Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
-- Use of this source code is governed by a License that can be found in the LICENSE file.
-- SPDX-License-Identifier: BSD-3-Clause

-- +migrate Up

create schema auth;

create table auth.jwt_keys (
	id serial not null primary key,
	public_key bytea not null,
	created_at timestamp with time zone not null
);

create table auth.users (
	id serial not null primary key,
	email character varying(128) not null,
	name character varying(24) not null,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	unique (email),
	unique (name)
);

create table auth.groups (
	id serial not null primary key,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	name character varying (24) not null,
	description character varying (120) not null,
	unique(name)
);

create table auth.user_groups (
	user_id integer not null references auth.users (id),
	group_id integer not null references auth.groups (id),
	primary key (user_id, group_id)
);

create table auth.passwords (
	id serial not null primary key,
	user_id integer not null references auth.users(id),
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	salt bytea not null,
	hash bytea not null,
	unique(user_id)
);

create table auth.audiences (
	id serial not null primary key,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	name character varying (24) not null,
	description character varying (120) not null,
	unique(name)
);

insert into auth.audiences (id, created_at, updated_at, name, description) values (0, now(), now(), 'default', 'Default fallback group');

create table auth.user_audiences (
	user_id integer not null references auth.users (id),
	audience_id integer not null references auth.audiences (id),
	primary key (user_id, audience_id)
);

-- +migrate Down
drop table auth.user_audiences;
drop table auth.audiences;
drop table auth.passwords;
drop table auth.user_groups;
drop table auth.groups;
drop table auth.users;
drop table auth.jwt_keys;
drop schema auth;
