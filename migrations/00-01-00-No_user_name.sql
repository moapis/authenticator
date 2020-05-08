-- Copyright (c) 2020, Mohlmann Solutions SRL. All rights reserved.
-- Use of this source code is governed by a License that can be found in the LICENSE file.
-- SPDX-License-Identifier: BSD-3-Clause

-- +migrate Up

ALTER TABLE auth.users DROP CONSTRAINT users_name_key;

-- +migrate Down

ALTER TABLE auth.users ADD UNIQUE (name);