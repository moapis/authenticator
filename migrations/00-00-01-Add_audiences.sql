-- Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
-- Use of this source code is governed by a License that can be found in the LICENSE file.
-- SPDX-License-Identifier: BSD-3-Clause

-- +migrate Up

create table audiences (
	id serial not null primary key,
	created_at timestamp with time zone not null,
	updated_at timestamp with time zone not null,
	name character varying (24) not null,
	unique(name)
);

insert into audiences (id, created_at, updated_at, name) values (0, now(), now(), 'default');

create table user_audiences (
	user_id integer not null references users (id),
	audience_id integer not null references audiences (id),
	primary key (user_id, audience_id)
);

-- +migrate Down

drop table user_audiences;
drop table audiences;