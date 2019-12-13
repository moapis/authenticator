-- Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
-- Use of this source code is governed by a License that can be found in the LICENSE file.
-- SPDX-License-Identifier: BSD-3-Clause

-- +migrate Up

create table jwt_keys (
	id serial not null primary key,
	public_key bytea not null,
	created_at timestamp with time zone not null
);

create table users (
	id serial not null primary key,
	email character varying(128) not null,
	name character varying(24) not null,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	unique (email),
	unique (name)
);

create table groups (
	id serial not null primary key,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	name character varying (24) not null,
	description character varying (120) not null,
	unique(name)
);

create table user_groups (
	user_id integer not null references users (id),
	group_id integer not null references groups (id),
	primary key (user_id, group_id)
);

create table passwords (
	id serial not null primary key,
	user_id integer not null references users(id),
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	salt bytea not null,
	hash bytea not null,
	unique(user_id)
);

create table audiences (
	id serial not null primary key,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	name character varying (24) not null,
	description character varying (120) not null,
	unique(name)
);

insert into audiences (id, created_at, updated_at, name, description) values (0, now(), now(), 'default', 'Default fallback group');

create table user_audiences (
	user_id integer not null references users (id),
	audience_id integer not null references audiences (id),
	primary key (user_id, audience_id)
);

-- +migrate Down
drop table user_audiences;
drop table audiences;
drop table passwords;
drop table user_groups;
drop table groups;
drop table users;
drop table jwt_keys;