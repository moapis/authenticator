// Code generated by SQLBoiler 3.6.0 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"github.com/volatiletech/sqlboiler/queries/qmhelper"
	"github.com/volatiletech/sqlboiler/strmangle"
)

// Group is an object representing the database table.
type Group struct {
	ID        int       `boil:"id" json:"id" toml:"id" yaml:"id"`
	CreatedAt time.Time `boil:"created_at" json:"created_at" toml:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `boil:"updated_at" json:"updated_at" toml:"updated_at" yaml:"updated_at"`
	Name      string    `boil:"name" json:"name" toml:"name" yaml:"name"`

	R *groupR `boil:"-" json:"-" toml:"-" yaml:"-"`
	L groupL  `boil:"-" json:"-" toml:"-" yaml:"-"`
}

var GroupColumns = struct {
	ID        string
	CreatedAt string
	UpdatedAt string
	Name      string
}{
	ID:        "id",
	CreatedAt: "created_at",
	UpdatedAt: "updated_at",
	Name:      "name",
}

// Generated where

type whereHelperint struct{ field string }

func (w whereHelperint) EQ(x int) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.EQ, x) }
func (w whereHelperint) NEQ(x int) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.NEQ, x) }
func (w whereHelperint) LT(x int) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.LT, x) }
func (w whereHelperint) LTE(x int) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.LTE, x) }
func (w whereHelperint) GT(x int) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.GT, x) }
func (w whereHelperint) GTE(x int) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.GTE, x) }
func (w whereHelperint) IN(slice []int) qm.QueryMod {
	values := make([]interface{}, 0, len(slice))
	for _, value := range slice {
		values = append(values, value)
	}
	return qm.WhereIn(fmt.Sprintf("%s IN ?", w.field), values...)
}

type whereHelpertime_Time struct{ field string }

func (w whereHelpertime_Time) EQ(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.EQ, x)
}
func (w whereHelpertime_Time) NEQ(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.NEQ, x)
}
func (w whereHelpertime_Time) LT(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.LT, x)
}
func (w whereHelpertime_Time) LTE(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.LTE, x)
}
func (w whereHelpertime_Time) GT(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.GT, x)
}
func (w whereHelpertime_Time) GTE(x time.Time) qm.QueryMod {
	return qmhelper.Where(w.field, qmhelper.GTE, x)
}

type whereHelperstring struct{ field string }

func (w whereHelperstring) EQ(x string) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.EQ, x) }
func (w whereHelperstring) NEQ(x string) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.NEQ, x) }
func (w whereHelperstring) LT(x string) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.LT, x) }
func (w whereHelperstring) LTE(x string) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.LTE, x) }
func (w whereHelperstring) GT(x string) qm.QueryMod  { return qmhelper.Where(w.field, qmhelper.GT, x) }
func (w whereHelperstring) GTE(x string) qm.QueryMod { return qmhelper.Where(w.field, qmhelper.GTE, x) }
func (w whereHelperstring) IN(slice []string) qm.QueryMod {
	values := make([]interface{}, 0, len(slice))
	for _, value := range slice {
		values = append(values, value)
	}
	return qm.WhereIn(fmt.Sprintf("%s IN ?", w.field), values...)
}

var GroupWhere = struct {
	ID        whereHelperint
	CreatedAt whereHelpertime_Time
	UpdatedAt whereHelpertime_Time
	Name      whereHelperstring
}{
	ID:        whereHelperint{field: "\"groups\".\"id\""},
	CreatedAt: whereHelpertime_Time{field: "\"groups\".\"created_at\""},
	UpdatedAt: whereHelpertime_Time{field: "\"groups\".\"updated_at\""},
	Name:      whereHelperstring{field: "\"groups\".\"name\""},
}

// GroupRels is where relationship names are stored.
var GroupRels = struct {
	Users string
}{
	Users: "Users",
}

// groupR is where relationships are stored.
type groupR struct {
	Users UserSlice
}

// NewStruct creates a new relationship struct
func (*groupR) NewStruct() *groupR {
	return &groupR{}
}

// groupL is where Load methods for each relationship are stored.
type groupL struct{}

var (
	groupAllColumns            = []string{"id", "created_at", "updated_at", "name"}
	groupColumnsWithoutDefault = []string{"created_at", "updated_at", "name"}
	groupColumnsWithDefault    = []string{"id"}
	groupPrimaryKeyColumns     = []string{"id"}
)

type (
	// GroupSlice is an alias for a slice of pointers to Group.
	// This should generally be used opposed to []Group.
	GroupSlice []*Group
	// GroupHook is the signature for custom Group hook methods
	GroupHook func(context.Context, boil.ContextExecutor, *Group) error

	groupQuery struct {
		*queries.Query
	}
)

// Cache for insert, update and upsert
var (
	groupType                 = reflect.TypeOf(&Group{})
	groupMapping              = queries.MakeStructMapping(groupType)
	groupPrimaryKeyMapping, _ = queries.BindMapping(groupType, groupMapping, groupPrimaryKeyColumns)
	groupInsertCacheMut       sync.RWMutex
	groupInsertCache          = make(map[string]insertCache)
	groupUpdateCacheMut       sync.RWMutex
	groupUpdateCache          = make(map[string]updateCache)
	groupUpsertCacheMut       sync.RWMutex
	groupUpsertCache          = make(map[string]insertCache)
)

var (
	// Force time package dependency for automated UpdatedAt/CreatedAt.
	_ = time.Second
	// Force qmhelper dependency for where clause generation (which doesn't
	// always happen)
	_ = qmhelper.Where
)

var groupBeforeInsertHooks []GroupHook
var groupBeforeUpdateHooks []GroupHook
var groupBeforeDeleteHooks []GroupHook
var groupBeforeUpsertHooks []GroupHook

var groupAfterInsertHooks []GroupHook
var groupAfterSelectHooks []GroupHook
var groupAfterUpdateHooks []GroupHook
var groupAfterDeleteHooks []GroupHook
var groupAfterUpsertHooks []GroupHook

// doBeforeInsertHooks executes all "before insert" hooks.
func (o *Group) doBeforeInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupBeforeInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpdateHooks executes all "before Update" hooks.
func (o *Group) doBeforeUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupBeforeUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeDeleteHooks executes all "before Delete" hooks.
func (o *Group) doBeforeDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupBeforeDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doBeforeUpsertHooks executes all "before Upsert" hooks.
func (o *Group) doBeforeUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupBeforeUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterInsertHooks executes all "after Insert" hooks.
func (o *Group) doAfterInsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupAfterInsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterSelectHooks executes all "after Select" hooks.
func (o *Group) doAfterSelectHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupAfterSelectHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpdateHooks executes all "after Update" hooks.
func (o *Group) doAfterUpdateHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupAfterUpdateHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterDeleteHooks executes all "after Delete" hooks.
func (o *Group) doAfterDeleteHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupAfterDeleteHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// doAfterUpsertHooks executes all "after Upsert" hooks.
func (o *Group) doAfterUpsertHooks(ctx context.Context, exec boil.ContextExecutor) (err error) {
	if boil.HooksAreSkipped(ctx) {
		return nil
	}

	for _, hook := range groupAfterUpsertHooks {
		if err := hook(ctx, exec, o); err != nil {
			return err
		}
	}

	return nil
}

// AddGroupHook registers your hook function for all future operations.
func AddGroupHook(hookPoint boil.HookPoint, groupHook GroupHook) {
	switch hookPoint {
	case boil.BeforeInsertHook:
		groupBeforeInsertHooks = append(groupBeforeInsertHooks, groupHook)
	case boil.BeforeUpdateHook:
		groupBeforeUpdateHooks = append(groupBeforeUpdateHooks, groupHook)
	case boil.BeforeDeleteHook:
		groupBeforeDeleteHooks = append(groupBeforeDeleteHooks, groupHook)
	case boil.BeforeUpsertHook:
		groupBeforeUpsertHooks = append(groupBeforeUpsertHooks, groupHook)
	case boil.AfterInsertHook:
		groupAfterInsertHooks = append(groupAfterInsertHooks, groupHook)
	case boil.AfterSelectHook:
		groupAfterSelectHooks = append(groupAfterSelectHooks, groupHook)
	case boil.AfterUpdateHook:
		groupAfterUpdateHooks = append(groupAfterUpdateHooks, groupHook)
	case boil.AfterDeleteHook:
		groupAfterDeleteHooks = append(groupAfterDeleteHooks, groupHook)
	case boil.AfterUpsertHook:
		groupAfterUpsertHooks = append(groupAfterUpsertHooks, groupHook)
	}
}

// One returns a single group record from the query.
func (q groupQuery) One(ctx context.Context, exec boil.ContextExecutor) (*Group, error) {
	o := &Group{}

	queries.SetLimit(q.Query, 1)

	err := q.Bind(ctx, exec, o)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: failed to execute a one query for groups")
	}

	if err := o.doAfterSelectHooks(ctx, exec); err != nil {
		return o, err
	}

	return o, nil
}

// All returns all Group records from the query.
func (q groupQuery) All(ctx context.Context, exec boil.ContextExecutor) (GroupSlice, error) {
	var o []*Group

	err := q.Bind(ctx, exec, &o)
	if err != nil {
		return nil, errors.Wrap(err, "models: failed to assign all query results to Group slice")
	}

	if len(groupAfterSelectHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterSelectHooks(ctx, exec); err != nil {
				return o, err
			}
		}
	}

	return o, nil
}

// Count returns the count of all Group records in the query.
func (q groupQuery) Count(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to count groups rows")
	}

	return count, nil
}

// Exists checks if the row exists in the table.
func (q groupQuery) Exists(ctx context.Context, exec boil.ContextExecutor) (bool, error) {
	var count int64

	queries.SetSelect(q.Query, nil)
	queries.SetCount(q.Query)
	queries.SetLimit(q.Query, 1)

	err := q.Query.QueryRowContext(ctx, exec).Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "models: failed to check if groups exists")
	}

	return count > 0, nil
}

// Users retrieves all the user's Users with an executor.
func (o *Group) Users(mods ...qm.QueryMod) userQuery {
	var queryMods []qm.QueryMod
	if len(mods) != 0 {
		queryMods = append(queryMods, mods...)
	}

	queryMods = append(queryMods,
		qm.InnerJoin("\"user_groups\" on \"users\".\"id\" = \"user_groups\".\"user_id\""),
		qm.Where("\"user_groups\".\"group_id\"=?", o.ID),
	)

	query := Users(queryMods...)
	queries.SetFrom(query.Query, "\"users\"")

	if len(queries.GetSelect(query.Query)) == 0 {
		queries.SetSelect(query.Query, []string{"\"users\".*"})
	}

	return query
}

// LoadUsers allows an eager lookup of values, cached into the
// loaded structs of the objects. This is for a 1-M or N-M relationship.
func (groupL) LoadUsers(ctx context.Context, e boil.ContextExecutor, singular bool, maybeGroup interface{}, mods queries.Applicator) error {
	var slice []*Group
	var object *Group

	if singular {
		object = maybeGroup.(*Group)
	} else {
		slice = *maybeGroup.(*[]*Group)
	}

	args := make([]interface{}, 0, 1)
	if singular {
		if object.R == nil {
			object.R = &groupR{}
		}
		args = append(args, object.ID)
	} else {
	Outer:
		for _, obj := range slice {
			if obj.R == nil {
				obj.R = &groupR{}
			}

			for _, a := range args {
				if a == obj.ID {
					continue Outer
				}
			}

			args = append(args, obj.ID)
		}
	}

	if len(args) == 0 {
		return nil
	}

	query := NewQuery(
		qm.Select("\"users\".*, \"a\".\"group_id\""),
		qm.From("\"users\""),
		qm.InnerJoin("\"user_groups\" as \"a\" on \"users\".\"id\" = \"a\".\"user_id\""),
		qm.WhereIn("\"a\".\"group_id\" in ?", args...),
	)
	if mods != nil {
		mods.Apply(query)
	}

	results, err := query.QueryContext(ctx, e)
	if err != nil {
		return errors.Wrap(err, "failed to eager load users")
	}

	var resultSlice []*User

	var localJoinCols []int
	for results.Next() {
		one := new(User)
		var localJoinCol int

		err = results.Scan(&one.ID, &one.Email, &one.Name, &one.CreatedAt, &one.UpdatedAt, &localJoinCol)
		if err != nil {
			return errors.Wrap(err, "failed to scan eager loaded results for users")
		}
		if err = results.Err(); err != nil {
			return errors.Wrap(err, "failed to plebian-bind eager loaded slice users")
		}

		resultSlice = append(resultSlice, one)
		localJoinCols = append(localJoinCols, localJoinCol)
	}

	if err = results.Close(); err != nil {
		return errors.Wrap(err, "failed to close results in eager load on users")
	}
	if err = results.Err(); err != nil {
		return errors.Wrap(err, "error occurred during iteration of eager loaded relations for users")
	}

	if len(userAfterSelectHooks) != 0 {
		for _, obj := range resultSlice {
			if err := obj.doAfterSelectHooks(ctx, e); err != nil {
				return err
			}
		}
	}
	if singular {
		object.R.Users = resultSlice
		for _, foreign := range resultSlice {
			if foreign.R == nil {
				foreign.R = &userR{}
			}
			foreign.R.Groups = append(foreign.R.Groups, object)
		}
		return nil
	}

	for i, foreign := range resultSlice {
		localJoinCol := localJoinCols[i]
		for _, local := range slice {
			if local.ID == localJoinCol {
				local.R.Users = append(local.R.Users, foreign)
				if foreign.R == nil {
					foreign.R = &userR{}
				}
				foreign.R.Groups = append(foreign.R.Groups, local)
				break
			}
		}
	}

	return nil
}

// AddUsers adds the given related objects to the existing relationships
// of the group, optionally inserting them as new records.
// Appends related to o.R.Users.
// Sets related.R.Groups appropriately.
func (o *Group) AddUsers(ctx context.Context, exec boil.ContextExecutor, insert bool, related ...*User) error {
	var err error
	for _, rel := range related {
		if insert {
			if err = rel.Insert(ctx, exec, boil.Infer()); err != nil {
				return errors.Wrap(err, "failed to insert into foreign table")
			}
		}
	}

	for _, rel := range related {
		query := "insert into \"user_groups\" (\"group_id\", \"user_id\") values ($1, $2)"
		values := []interface{}{o.ID, rel.ID}

		if boil.IsDebug(ctx) {
			writer := boil.DebugWriterFrom(ctx)
			fmt.Fprintln(writer, query)
			fmt.Fprintln(writer, values)
		}
		_, err = exec.ExecContext(ctx, query, values...)
		if err != nil {
			return errors.Wrap(err, "failed to insert into join table")
		}
	}
	if o.R == nil {
		o.R = &groupR{
			Users: related,
		}
	} else {
		o.R.Users = append(o.R.Users, related...)
	}

	for _, rel := range related {
		if rel.R == nil {
			rel.R = &userR{
				Groups: GroupSlice{o},
			}
		} else {
			rel.R.Groups = append(rel.R.Groups, o)
		}
	}
	return nil
}

// SetUsers removes all previously related items of the
// group replacing them completely with the passed
// in related items, optionally inserting them as new records.
// Sets o.R.Groups's Users accordingly.
// Replaces o.R.Users with related.
// Sets related.R.Groups's Users accordingly.
func (o *Group) SetUsers(ctx context.Context, exec boil.ContextExecutor, insert bool, related ...*User) error {
	query := "delete from \"user_groups\" where \"group_id\" = $1"
	values := []interface{}{o.ID}
	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, query)
		fmt.Fprintln(writer, values)
	}
	_, err := exec.ExecContext(ctx, query, values...)
	if err != nil {
		return errors.Wrap(err, "failed to remove relationships before set")
	}

	removeUsersFromGroupsSlice(o, related)
	if o.R != nil {
		o.R.Users = nil
	}
	return o.AddUsers(ctx, exec, insert, related...)
}

// RemoveUsers relationships from objects passed in.
// Removes related items from R.Users (uses pointer comparison, removal does not keep order)
// Sets related.R.Groups.
func (o *Group) RemoveUsers(ctx context.Context, exec boil.ContextExecutor, related ...*User) error {
	var err error
	query := fmt.Sprintf(
		"delete from \"user_groups\" where \"group_id\" = $1 and \"user_id\" in (%s)",
		strmangle.Placeholders(dialect.UseIndexPlaceholders, len(related), 2, 1),
	)
	values := []interface{}{o.ID}
	for _, rel := range related {
		values = append(values, rel.ID)
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, query)
		fmt.Fprintln(writer, values)
	}
	_, err = exec.ExecContext(ctx, query, values...)
	if err != nil {
		return errors.Wrap(err, "failed to remove relationships before set")
	}
	removeUsersFromGroupsSlice(o, related)
	if o.R == nil {
		return nil
	}

	for _, rel := range related {
		for i, ri := range o.R.Users {
			if rel != ri {
				continue
			}

			ln := len(o.R.Users)
			if ln > 1 && i < ln-1 {
				o.R.Users[i] = o.R.Users[ln-1]
			}
			o.R.Users = o.R.Users[:ln-1]
			break
		}
	}

	return nil
}

func removeUsersFromGroupsSlice(o *Group, related []*User) {
	for _, rel := range related {
		if rel.R == nil {
			continue
		}
		for i, ri := range rel.R.Groups {
			if o.ID != ri.ID {
				continue
			}

			ln := len(rel.R.Groups)
			if ln > 1 && i < ln-1 {
				rel.R.Groups[i] = rel.R.Groups[ln-1]
			}
			rel.R.Groups = rel.R.Groups[:ln-1]
			break
		}
	}
}

// Groups retrieves all the records using an executor.
func Groups(mods ...qm.QueryMod) groupQuery {
	mods = append(mods, qm.From("\"groups\""))
	return groupQuery{NewQuery(mods...)}
}

// FindGroup retrieves a single record by ID with an executor.
// If selectCols is empty Find will return all columns.
func FindGroup(ctx context.Context, exec boil.ContextExecutor, iD int, selectCols ...string) (*Group, error) {
	groupObj := &Group{}

	sel := "*"
	if len(selectCols) > 0 {
		sel = strings.Join(strmangle.IdentQuoteSlice(dialect.LQ, dialect.RQ, selectCols), ",")
	}
	query := fmt.Sprintf(
		"select %s from \"groups\" where \"id\"=$1", sel,
	)

	q := queries.Raw(query, iD)

	err := q.Bind(ctx, exec, groupObj)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, errors.Wrap(err, "models: unable to select from groups")
	}

	return groupObj, nil
}

// Insert a single record using an executor.
// See boil.Columns.InsertColumnSet documentation to understand column list inference for inserts.
func (o *Group) Insert(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) error {
	if o == nil {
		return errors.New("models: no groups provided for insertion")
	}

	var err error
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if o.CreatedAt.IsZero() {
			o.CreatedAt = currTime
		}
		if o.UpdatedAt.IsZero() {
			o.UpdatedAt = currTime
		}
	}

	if err := o.doBeforeInsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(groupColumnsWithDefault, o)

	key := makeCacheKey(columns, nzDefaults)
	groupInsertCacheMut.RLock()
	cache, cached := groupInsertCache[key]
	groupInsertCacheMut.RUnlock()

	if !cached {
		wl, returnColumns := columns.InsertColumnSet(
			groupAllColumns,
			groupColumnsWithDefault,
			groupColumnsWithoutDefault,
			nzDefaults,
		)

		cache.valueMapping, err = queries.BindMapping(groupType, groupMapping, wl)
		if err != nil {
			return err
		}
		cache.retMapping, err = queries.BindMapping(groupType, groupMapping, returnColumns)
		if err != nil {
			return err
		}
		if len(wl) != 0 {
			cache.query = fmt.Sprintf("INSERT INTO \"groups\" (\"%s\") %%sVALUES (%s)%%s", strings.Join(wl, "\",\""), strmangle.Placeholders(dialect.UseIndexPlaceholders, len(wl), 1, 1))
		} else {
			cache.query = "INSERT INTO \"groups\" %sDEFAULT VALUES%s"
		}

		var queryOutput, queryReturning string

		if len(cache.retMapping) != 0 {
			queryReturning = fmt.Sprintf(" RETURNING \"%s\"", strings.Join(returnColumns, "\",\""))
		}

		cache.query = fmt.Sprintf(cache.query, queryOutput, queryReturning)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	vals := queries.ValuesFromMapping(value, cache.valueMapping)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, vals)
	}

	if len(cache.retMapping) != 0 {
		err = exec.QueryRowContext(ctx, cache.query, vals...).Scan(queries.PtrsFromMapping(value, cache.retMapping)...)
	} else {
		_, err = exec.ExecContext(ctx, cache.query, vals...)
	}

	if err != nil {
		return errors.Wrap(err, "models: unable to insert into groups")
	}

	if !cached {
		groupInsertCacheMut.Lock()
		groupInsertCache[key] = cache
		groupInsertCacheMut.Unlock()
	}

	return o.doAfterInsertHooks(ctx, exec)
}

// Update uses an executor to update the Group.
// See boil.Columns.UpdateColumnSet documentation to understand column list inference for updates.
// Update does not automatically update the record in case of default values. Use .Reload() to refresh the records.
func (o *Group) Update(ctx context.Context, exec boil.ContextExecutor, columns boil.Columns) (int64, error) {
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		o.UpdatedAt = currTime
	}

	var err error
	if err = o.doBeforeUpdateHooks(ctx, exec); err != nil {
		return 0, err
	}
	key := makeCacheKey(columns, nil)
	groupUpdateCacheMut.RLock()
	cache, cached := groupUpdateCache[key]
	groupUpdateCacheMut.RUnlock()

	if !cached {
		wl := columns.UpdateColumnSet(
			groupAllColumns,
			groupPrimaryKeyColumns,
		)

		if !columns.IsWhitelist() {
			wl = strmangle.SetComplement(wl, []string{"created_at"})
		}
		if len(wl) == 0 {
			return 0, errors.New("models: unable to update groups, could not build whitelist")
		}

		cache.query = fmt.Sprintf("UPDATE \"groups\" SET %s WHERE %s",
			strmangle.SetParamNames("\"", "\"", 1, wl),
			strmangle.WhereClause("\"", "\"", len(wl)+1, groupPrimaryKeyColumns),
		)
		cache.valueMapping, err = queries.BindMapping(groupType, groupMapping, append(wl, groupPrimaryKeyColumns...))
		if err != nil {
			return 0, err
		}
	}

	values := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), cache.valueMapping)

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, values)
	}
	var result sql.Result
	result, err = exec.ExecContext(ctx, cache.query, values...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update groups row")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by update for groups")
	}

	if !cached {
		groupUpdateCacheMut.Lock()
		groupUpdateCache[key] = cache
		groupUpdateCacheMut.Unlock()
	}

	return rowsAff, o.doAfterUpdateHooks(ctx, exec)
}

// UpdateAll updates all rows with the specified column values.
func (q groupQuery) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	queries.SetUpdate(q.Query, cols)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all for groups")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected for groups")
	}

	return rowsAff, nil
}

// UpdateAll updates all rows with the specified column values, using an executor.
func (o GroupSlice) UpdateAll(ctx context.Context, exec boil.ContextExecutor, cols M) (int64, error) {
	ln := int64(len(o))
	if ln == 0 {
		return 0, nil
	}

	if len(cols) == 0 {
		return 0, errors.New("models: update all requires at least one column argument")
	}

	colNames := make([]string, len(cols))
	args := make([]interface{}, len(cols))

	i := 0
	for name, value := range cols {
		colNames[i] = name
		args[i] = value
		i++
	}

	// Append all of the primary key values for each column
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), groupPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := fmt.Sprintf("UPDATE \"groups\" SET %s WHERE %s",
		strmangle.SetParamNames("\"", "\"", 1, colNames),
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), len(colNames)+1, groupPrimaryKeyColumns, len(o)))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to update all in group slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to retrieve rows affected all in update all group")
	}
	return rowsAff, nil
}

// Upsert attempts an insert using an executor, and does an update or ignore on conflict.
// See boil.Columns documentation for how to properly use updateColumns and insertColumns.
func (o *Group) Upsert(ctx context.Context, exec boil.ContextExecutor, updateOnConflict bool, conflictColumns []string, updateColumns, insertColumns boil.Columns) error {
	if o == nil {
		return errors.New("models: no groups provided for upsert")
	}
	if !boil.TimestampsAreSkipped(ctx) {
		currTime := time.Now().In(boil.GetLocation())

		if o.CreatedAt.IsZero() {
			o.CreatedAt = currTime
		}
		o.UpdatedAt = currTime
	}

	if err := o.doBeforeUpsertHooks(ctx, exec); err != nil {
		return err
	}

	nzDefaults := queries.NonZeroDefaultSet(groupColumnsWithDefault, o)

	// Build cache key in-line uglily - mysql vs psql problems
	buf := strmangle.GetBuffer()
	if updateOnConflict {
		buf.WriteByte('t')
	} else {
		buf.WriteByte('f')
	}
	buf.WriteByte('.')
	for _, c := range conflictColumns {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	buf.WriteString(strconv.Itoa(updateColumns.Kind))
	for _, c := range updateColumns.Cols {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	buf.WriteString(strconv.Itoa(insertColumns.Kind))
	for _, c := range insertColumns.Cols {
		buf.WriteString(c)
	}
	buf.WriteByte('.')
	for _, c := range nzDefaults {
		buf.WriteString(c)
	}
	key := buf.String()
	strmangle.PutBuffer(buf)

	groupUpsertCacheMut.RLock()
	cache, cached := groupUpsertCache[key]
	groupUpsertCacheMut.RUnlock()

	var err error

	if !cached {
		insert, ret := insertColumns.InsertColumnSet(
			groupAllColumns,
			groupColumnsWithDefault,
			groupColumnsWithoutDefault,
			nzDefaults,
		)
		update := updateColumns.UpdateColumnSet(
			groupAllColumns,
			groupPrimaryKeyColumns,
		)

		if updateOnConflict && len(update) == 0 {
			return errors.New("models: unable to upsert groups, could not build update column list")
		}

		conflict := conflictColumns
		if len(conflict) == 0 {
			conflict = make([]string, len(groupPrimaryKeyColumns))
			copy(conflict, groupPrimaryKeyColumns)
		}
		cache.query = buildUpsertQueryPostgres(dialect, "\"groups\"", updateOnConflict, ret, update, conflict, insert)

		cache.valueMapping, err = queries.BindMapping(groupType, groupMapping, insert)
		if err != nil {
			return err
		}
		if len(ret) != 0 {
			cache.retMapping, err = queries.BindMapping(groupType, groupMapping, ret)
			if err != nil {
				return err
			}
		}
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	vals := queries.ValuesFromMapping(value, cache.valueMapping)
	var returns []interface{}
	if len(cache.retMapping) != 0 {
		returns = queries.PtrsFromMapping(value, cache.retMapping)
	}

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, cache.query)
		fmt.Fprintln(writer, vals)
	}
	if len(cache.retMapping) != 0 {
		err = exec.QueryRowContext(ctx, cache.query, vals...).Scan(returns...)
		if err == sql.ErrNoRows {
			err = nil // Postgres doesn't return anything when there's no update
		}
	} else {
		_, err = exec.ExecContext(ctx, cache.query, vals...)
	}
	if err != nil {
		return errors.Wrap(err, "models: unable to upsert groups")
	}

	if !cached {
		groupUpsertCacheMut.Lock()
		groupUpsertCache[key] = cache
		groupUpsertCacheMut.Unlock()
	}

	return o.doAfterUpsertHooks(ctx, exec)
}

// Delete deletes a single Group record with an executor.
// Delete will match against the primary key column to find the record to delete.
func (o *Group) Delete(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if o == nil {
		return 0, errors.New("models: no Group provided for delete")
	}

	if err := o.doBeforeDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	args := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(o)), groupPrimaryKeyMapping)
	sql := "DELETE FROM \"groups\" WHERE \"id\"=$1"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args...)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete from groups")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by delete for groups")
	}

	if err := o.doAfterDeleteHooks(ctx, exec); err != nil {
		return 0, err
	}

	return rowsAff, nil
}

// DeleteAll deletes all matching rows.
func (q groupQuery) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if q.Query == nil {
		return 0, errors.New("models: no groupQuery provided for delete all")
	}

	queries.SetDelete(q.Query)

	result, err := q.Query.ExecContext(ctx, exec)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from groups")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for groups")
	}

	return rowsAff, nil
}

// DeleteAll deletes all rows in the slice, using an executor.
func (o GroupSlice) DeleteAll(ctx context.Context, exec boil.ContextExecutor) (int64, error) {
	if len(o) == 0 {
		return 0, nil
	}

	if len(groupBeforeDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doBeforeDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	var args []interface{}
	for _, obj := range o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), groupPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "DELETE FROM \"groups\" WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 1, groupPrimaryKeyColumns, len(o))

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, args)
	}
	result, err := exec.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "models: unable to delete all from group slice")
	}

	rowsAff, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "models: failed to get rows affected by deleteall for groups")
	}

	if len(groupAfterDeleteHooks) != 0 {
		for _, obj := range o {
			if err := obj.doAfterDeleteHooks(ctx, exec); err != nil {
				return 0, err
			}
		}
	}

	return rowsAff, nil
}

// Reload refetches the object from the database
// using the primary keys with an executor.
func (o *Group) Reload(ctx context.Context, exec boil.ContextExecutor) error {
	ret, err := FindGroup(ctx, exec, o.ID)
	if err != nil {
		return err
	}

	*o = *ret
	return nil
}

// ReloadAll refetches every row with matching primary key column values
// and overwrites the original object slice with the newly updated slice.
func (o *GroupSlice) ReloadAll(ctx context.Context, exec boil.ContextExecutor) error {
	if o == nil || len(*o) == 0 {
		return nil
	}

	slice := GroupSlice{}
	var args []interface{}
	for _, obj := range *o {
		pkeyArgs := queries.ValuesFromMapping(reflect.Indirect(reflect.ValueOf(obj)), groupPrimaryKeyMapping)
		args = append(args, pkeyArgs...)
	}

	sql := "SELECT \"groups\".* FROM \"groups\" WHERE " +
		strmangle.WhereClauseRepeated(string(dialect.LQ), string(dialect.RQ), 1, groupPrimaryKeyColumns, len(*o))

	q := queries.Raw(sql, args...)

	err := q.Bind(ctx, exec, &slice)
	if err != nil {
		return errors.Wrap(err, "models: unable to reload all in GroupSlice")
	}

	*o = slice

	return nil
}

// GroupExists checks if the Group row exists.
func GroupExists(ctx context.Context, exec boil.ContextExecutor, iD int) (bool, error) {
	var exists bool
	sql := "select exists(select 1 from \"groups\" where \"id\"=$1 limit 1)"

	if boil.IsDebug(ctx) {
		writer := boil.DebugWriterFrom(ctx)
		fmt.Fprintln(writer, sql)
		fmt.Fprintln(writer, iD)
	}
	row := exec.QueryRowContext(ctx, sql, iD)

	err := row.Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, "models: unable to check if groups exists")
	}

	return exists, nil
}
