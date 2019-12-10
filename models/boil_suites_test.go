// Code generated by SQLBoiler 3.6.0 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import "testing"

// This test suite runs each operation test in parallel.
// Example, if your database has 3 tables, the suite will run:
// table1, table2 and table3 Delete in parallel
// table1, table2 and table3 Insert in parallel, and so forth.
// It does NOT run each operation group in parallel.
// Separating the tests thusly grants avoidance of Postgres deadlocks.
func TestParent(t *testing.T) {
	t.Run("Audiences", testAudiences)
	t.Run("Groups", testGroups)
	t.Run("JWTKeys", testJWTKeys)
	t.Run("Migrations", testMigrations)
	t.Run("Passwords", testPasswords)
	t.Run("Users", testUsers)
}

func TestDelete(t *testing.T) {
	t.Run("Audiences", testAudiencesDelete)
	t.Run("Groups", testGroupsDelete)
	t.Run("JWTKeys", testJWTKeysDelete)
	t.Run("Migrations", testMigrationsDelete)
	t.Run("Passwords", testPasswordsDelete)
	t.Run("Users", testUsersDelete)
}

func TestQueryDeleteAll(t *testing.T) {
	t.Run("Audiences", testAudiencesQueryDeleteAll)
	t.Run("Groups", testGroupsQueryDeleteAll)
	t.Run("JWTKeys", testJWTKeysQueryDeleteAll)
	t.Run("Migrations", testMigrationsQueryDeleteAll)
	t.Run("Passwords", testPasswordsQueryDeleteAll)
	t.Run("Users", testUsersQueryDeleteAll)
}

func TestSliceDeleteAll(t *testing.T) {
	t.Run("Audiences", testAudiencesSliceDeleteAll)
	t.Run("Groups", testGroupsSliceDeleteAll)
	t.Run("JWTKeys", testJWTKeysSliceDeleteAll)
	t.Run("Migrations", testMigrationsSliceDeleteAll)
	t.Run("Passwords", testPasswordsSliceDeleteAll)
	t.Run("Users", testUsersSliceDeleteAll)
}

func TestExists(t *testing.T) {
	t.Run("Audiences", testAudiencesExists)
	t.Run("Groups", testGroupsExists)
	t.Run("JWTKeys", testJWTKeysExists)
	t.Run("Migrations", testMigrationsExists)
	t.Run("Passwords", testPasswordsExists)
	t.Run("Users", testUsersExists)
}

func TestFind(t *testing.T) {
	t.Run("Audiences", testAudiencesFind)
	t.Run("Groups", testGroupsFind)
	t.Run("JWTKeys", testJWTKeysFind)
	t.Run("Migrations", testMigrationsFind)
	t.Run("Passwords", testPasswordsFind)
	t.Run("Users", testUsersFind)
}

func TestBind(t *testing.T) {
	t.Run("Audiences", testAudiencesBind)
	t.Run("Groups", testGroupsBind)
	t.Run("JWTKeys", testJWTKeysBind)
	t.Run("Migrations", testMigrationsBind)
	t.Run("Passwords", testPasswordsBind)
	t.Run("Users", testUsersBind)
}

func TestOne(t *testing.T) {
	t.Run("Audiences", testAudiencesOne)
	t.Run("Groups", testGroupsOne)
	t.Run("JWTKeys", testJWTKeysOne)
	t.Run("Migrations", testMigrationsOne)
	t.Run("Passwords", testPasswordsOne)
	t.Run("Users", testUsersOne)
}

func TestAll(t *testing.T) {
	t.Run("Audiences", testAudiencesAll)
	t.Run("Groups", testGroupsAll)
	t.Run("JWTKeys", testJWTKeysAll)
	t.Run("Migrations", testMigrationsAll)
	t.Run("Passwords", testPasswordsAll)
	t.Run("Users", testUsersAll)
}

func TestCount(t *testing.T) {
	t.Run("Audiences", testAudiencesCount)
	t.Run("Groups", testGroupsCount)
	t.Run("JWTKeys", testJWTKeysCount)
	t.Run("Migrations", testMigrationsCount)
	t.Run("Passwords", testPasswordsCount)
	t.Run("Users", testUsersCount)
}

func TestHooks(t *testing.T) {
	t.Run("Audiences", testAudiencesHooks)
	t.Run("Groups", testGroupsHooks)
	t.Run("JWTKeys", testJWTKeysHooks)
	t.Run("Migrations", testMigrationsHooks)
	t.Run("Passwords", testPasswordsHooks)
	t.Run("Users", testUsersHooks)
}

func TestInsert(t *testing.T) {
	t.Run("Audiences", testAudiencesInsert)
	t.Run("Audiences", testAudiencesInsertWhitelist)
	t.Run("Groups", testGroupsInsert)
	t.Run("Groups", testGroupsInsertWhitelist)
	t.Run("JWTKeys", testJWTKeysInsert)
	t.Run("JWTKeys", testJWTKeysInsertWhitelist)
	t.Run("Migrations", testMigrationsInsert)
	t.Run("Migrations", testMigrationsInsertWhitelist)
	t.Run("Passwords", testPasswordsInsert)
	t.Run("Passwords", testPasswordsInsertWhitelist)
	t.Run("Users", testUsersInsert)
	t.Run("Users", testUsersInsertWhitelist)
}

// TestToOne tests cannot be run in parallel
// or deadlocks can occur.
func TestToOne(t *testing.T) {
	t.Run("PasswordToUserUsingUser", testPasswordToOneUserUsingUser)
}

// TestOneToOne tests cannot be run in parallel
// or deadlocks can occur.
func TestOneToOne(t *testing.T) {
	t.Run("UserToPasswordUsingPassword", testUserOneToOnePasswordUsingPassword)
}

// TestToMany tests cannot be run in parallel
// or deadlocks can occur.
func TestToMany(t *testing.T) {
	t.Run("AudienceToUsers", testAudienceToManyUsers)
	t.Run("GroupToUsers", testGroupToManyUsers)
	t.Run("UserToAudiences", testUserToManyAudiences)
	t.Run("UserToGroups", testUserToManyGroups)
}

// TestToOneSet tests cannot be run in parallel
// or deadlocks can occur.
func TestToOneSet(t *testing.T) {
	t.Run("PasswordToUserUsingPassword", testPasswordToOneSetOpUserUsingUser)
}

// TestToOneRemove tests cannot be run in parallel
// or deadlocks can occur.
func TestToOneRemove(t *testing.T) {}

// TestOneToOneSet tests cannot be run in parallel
// or deadlocks can occur.
func TestOneToOneSet(t *testing.T) {
	t.Run("UserToPasswordUsingPassword", testUserOneToOneSetOpPasswordUsingPassword)
}

// TestOneToOneRemove tests cannot be run in parallel
// or deadlocks can occur.
func TestOneToOneRemove(t *testing.T) {}

// TestToManyAdd tests cannot be run in parallel
// or deadlocks can occur.
func TestToManyAdd(t *testing.T) {
	t.Run("AudienceToUsers", testAudienceToManyAddOpUsers)
	t.Run("GroupToUsers", testGroupToManyAddOpUsers)
	t.Run("UserToAudiences", testUserToManyAddOpAudiences)
	t.Run("UserToGroups", testUserToManyAddOpGroups)
}

// TestToManySet tests cannot be run in parallel
// or deadlocks can occur.
func TestToManySet(t *testing.T) {
	t.Run("AudienceToUsers", testAudienceToManySetOpUsers)
	t.Run("GroupToUsers", testGroupToManySetOpUsers)
	t.Run("UserToAudiences", testUserToManySetOpAudiences)
	t.Run("UserToGroups", testUserToManySetOpGroups)
}

// TestToManyRemove tests cannot be run in parallel
// or deadlocks can occur.
func TestToManyRemove(t *testing.T) {
	t.Run("AudienceToUsers", testAudienceToManyRemoveOpUsers)
	t.Run("GroupToUsers", testGroupToManyRemoveOpUsers)
	t.Run("UserToAudiences", testUserToManyRemoveOpAudiences)
	t.Run("UserToGroups", testUserToManyRemoveOpGroups)
}

func TestReload(t *testing.T) {
	t.Run("Audiences", testAudiencesReload)
	t.Run("Groups", testGroupsReload)
	t.Run("JWTKeys", testJWTKeysReload)
	t.Run("Migrations", testMigrationsReload)
	t.Run("Passwords", testPasswordsReload)
	t.Run("Users", testUsersReload)
}

func TestReloadAll(t *testing.T) {
	t.Run("Audiences", testAudiencesReloadAll)
	t.Run("Groups", testGroupsReloadAll)
	t.Run("JWTKeys", testJWTKeysReloadAll)
	t.Run("Migrations", testMigrationsReloadAll)
	t.Run("Passwords", testPasswordsReloadAll)
	t.Run("Users", testUsersReloadAll)
}

func TestSelect(t *testing.T) {
	t.Run("Audiences", testAudiencesSelect)
	t.Run("Groups", testGroupsSelect)
	t.Run("JWTKeys", testJWTKeysSelect)
	t.Run("Migrations", testMigrationsSelect)
	t.Run("Passwords", testPasswordsSelect)
	t.Run("Users", testUsersSelect)
}

func TestUpdate(t *testing.T) {
	t.Run("Audiences", testAudiencesUpdate)
	t.Run("Groups", testGroupsUpdate)
	t.Run("JWTKeys", testJWTKeysUpdate)
	t.Run("Migrations", testMigrationsUpdate)
	t.Run("Passwords", testPasswordsUpdate)
	t.Run("Users", testUsersUpdate)
}

func TestSliceUpdateAll(t *testing.T) {
	t.Run("Audiences", testAudiencesSliceUpdateAll)
	t.Run("Groups", testGroupsSliceUpdateAll)
	t.Run("JWTKeys", testJWTKeysSliceUpdateAll)
	t.Run("Migrations", testMigrationsSliceUpdateAll)
	t.Run("Passwords", testPasswordsSliceUpdateAll)
	t.Run("Users", testUsersSliceUpdateAll)
}
