-- +migrate Up

create table jwt_keys (
	id serial not null primary key,
	public_key bytea not null,
	created_at timestamp with time zone not null,
	unique (public_key)
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
	unique(name)
);

create table user_groups (
	user_id integer not null references users (id),
	group_id integer not null references groups (id),
	primary key (user_id, group_id)
);

create table passwords (
	user_id integer not null primary key references users(id),
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	salt bytea not null,
	hash bytea not null
);

-- +migrate Down
drop table passwords;
drop table user_groups;
drop table groups;
drop table users;
drop table jwt_keys;