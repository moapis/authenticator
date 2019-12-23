// Code generated by SQLBoiler 3.6.0 (https://github.com/volatiletech/sqlboiler). DO NOT EDIT.
// This file is meant to be re-generated in place and/or deleted at any time.

package models

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries"
	"github.com/volatiletech/sqlboiler/randomize"
	"github.com/volatiletech/sqlboiler/strmangle"
)

var (
	// Relationships sometimes use the reflection helper queries.Equal/queries.Assign
	// so force a package dependency in case they don't.
	_ = queries.Equal
)

func testAudiences(t *testing.T) {
	t.Parallel()

	query := Audiences()

	if query.Query == nil {
		t.Error("expected a query, got nothing")
	}
}

func testAudiencesDelete(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := o.Delete(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testAudiencesQueryDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if rowsAff, err := Audiences().DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testAudiencesSliceDeleteAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := AudienceSlice{o}

	if rowsAff, err := slice.DeleteAll(ctx, tx); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only have deleted one row, but affected:", rowsAff)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 0 {
		t.Error("want zero records, got:", count)
	}
}

func testAudiencesExists(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	e, err := AudienceExists(ctx, tx, o.ID)
	if err != nil {
		t.Errorf("Unable to check if Audience exists: %s", err)
	}
	if !e {
		t.Errorf("Expected AudienceExists to return true, but got false.")
	}
}

func testAudiencesFind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	audienceFound, err := FindAudience(ctx, tx, o.ID)
	if err != nil {
		t.Error(err)
	}

	if audienceFound == nil {
		t.Error("want a record, got nil")
	}
}

func testAudiencesBind(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = Audiences().Bind(ctx, tx, o); err != nil {
		t.Error(err)
	}
}

func testAudiencesOne(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if x, err := Audiences().One(ctx, tx); err != nil {
		t.Error(err)
	} else if x == nil {
		t.Error("expected to get a non nil record")
	}
}

func testAudiencesAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	audienceOne := &Audience{}
	audienceTwo := &Audience{}
	if err = randomize.Struct(seed, audienceOne, audienceDBTypes, false, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}
	if err = randomize.Struct(seed, audienceTwo, audienceDBTypes, false, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = audienceOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = audienceTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Audiences().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 2 {
		t.Error("want 2 records, got:", len(slice))
	}
}

func testAudiencesCount(t *testing.T) {
	t.Parallel()

	var err error
	seed := randomize.NewSeed()
	audienceOne := &Audience{}
	audienceTwo := &Audience{}
	if err = randomize.Struct(seed, audienceOne, audienceDBTypes, false, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}
	if err = randomize.Struct(seed, audienceTwo, audienceDBTypes, false, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = audienceOne.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}
	if err = audienceTwo.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 2 {
		t.Error("want 2 records, got:", count)
	}
}

func audienceBeforeInsertHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceAfterInsertHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceAfterSelectHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceBeforeUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceAfterUpdateHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceBeforeDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceAfterDeleteHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceBeforeUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func audienceAfterUpsertHook(ctx context.Context, e boil.ContextExecutor, o *Audience) error {
	*o = Audience{}
	return nil
}

func testAudiencesHooks(t *testing.T) {
	t.Parallel()

	var err error

	ctx := context.Background()
	empty := &Audience{}
	o := &Audience{}

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, o, audienceDBTypes, false); err != nil {
		t.Errorf("Unable to randomize Audience object: %s", err)
	}

	AddAudienceHook(boil.BeforeInsertHook, audienceBeforeInsertHook)
	if err = o.doBeforeInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeInsertHook function to empty object, but got: %#v", o)
	}
	audienceBeforeInsertHooks = []AudienceHook{}

	AddAudienceHook(boil.AfterInsertHook, audienceAfterInsertHook)
	if err = o.doAfterInsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterInsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterInsertHook function to empty object, but got: %#v", o)
	}
	audienceAfterInsertHooks = []AudienceHook{}

	AddAudienceHook(boil.AfterSelectHook, audienceAfterSelectHook)
	if err = o.doAfterSelectHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterSelectHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterSelectHook function to empty object, but got: %#v", o)
	}
	audienceAfterSelectHooks = []AudienceHook{}

	AddAudienceHook(boil.BeforeUpdateHook, audienceBeforeUpdateHook)
	if err = o.doBeforeUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpdateHook function to empty object, but got: %#v", o)
	}
	audienceBeforeUpdateHooks = []AudienceHook{}

	AddAudienceHook(boil.AfterUpdateHook, audienceAfterUpdateHook)
	if err = o.doAfterUpdateHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpdateHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpdateHook function to empty object, but got: %#v", o)
	}
	audienceAfterUpdateHooks = []AudienceHook{}

	AddAudienceHook(boil.BeforeDeleteHook, audienceBeforeDeleteHook)
	if err = o.doBeforeDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeDeleteHook function to empty object, but got: %#v", o)
	}
	audienceBeforeDeleteHooks = []AudienceHook{}

	AddAudienceHook(boil.AfterDeleteHook, audienceAfterDeleteHook)
	if err = o.doAfterDeleteHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterDeleteHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterDeleteHook function to empty object, but got: %#v", o)
	}
	audienceAfterDeleteHooks = []AudienceHook{}

	AddAudienceHook(boil.BeforeUpsertHook, audienceBeforeUpsertHook)
	if err = o.doBeforeUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doBeforeUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected BeforeUpsertHook function to empty object, but got: %#v", o)
	}
	audienceBeforeUpsertHooks = []AudienceHook{}

	AddAudienceHook(boil.AfterUpsertHook, audienceAfterUpsertHook)
	if err = o.doAfterUpsertHooks(ctx, nil); err != nil {
		t.Errorf("Unable to execute doAfterUpsertHooks: %s", err)
	}
	if !reflect.DeepEqual(o, empty) {
		t.Errorf("Expected AfterUpsertHook function to empty object, but got: %#v", o)
	}
	audienceAfterUpsertHooks = []AudienceHook{}
}

func testAudiencesInsert(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testAudiencesInsertWhitelist(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Whitelist(audienceColumnsWithoutDefault...)); err != nil {
		t.Error(err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}
}

func testAudienceToManyUsers(t *testing.T) {
	var err error
	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Audience
	var b, c User

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	if err = randomize.Struct(seed, &b, userDBTypes, false, userColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}
	if err = randomize.Struct(seed, &c, userDBTypes, false, userColumnsWithDefault...); err != nil {
		t.Fatal(err)
	}

	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	_, err = tx.Exec("insert into \"auth\".\"user_audiences\" (\"audience_id\", \"user_id\") values ($1, $2)", a.ID, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("insert into \"auth\".\"user_audiences\" (\"audience_id\", \"user_id\") values ($1, $2)", a.ID, c.ID)
	if err != nil {
		t.Fatal(err)
	}

	check, err := a.Users().All(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	bFound, cFound := false, false
	for _, v := range check {
		if v.ID == b.ID {
			bFound = true
		}
		if v.ID == c.ID {
			cFound = true
		}
	}

	if !bFound {
		t.Error("expected to find b")
	}
	if !cFound {
		t.Error("expected to find c")
	}

	slice := AudienceSlice{&a}
	if err = a.L.LoadUsers(ctx, tx, false, (*[]*Audience)(&slice), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.Users); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	a.R.Users = nil
	if err = a.L.LoadUsers(ctx, tx, true, &a, nil); err != nil {
		t.Fatal(err)
	}
	if got := len(a.R.Users); got != 2 {
		t.Error("number of eager loaded records wrong, got:", got)
	}

	if t.Failed() {
		t.Logf("%#v", check)
	}
}

func testAudienceToManyAddOpUsers(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Audience
	var b, c, d, e User

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, audienceDBTypes, false, strmangle.SetComplement(audiencePrimaryKeyColumns, audienceColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*User{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, userDBTypes, false, strmangle.SetComplement(userPrimaryKeyColumns, userColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	foreignersSplitByInsertion := [][]*User{
		{&b, &c},
		{&d, &e},
	}

	for i, x := range foreignersSplitByInsertion {
		err = a.AddUsers(ctx, tx, i != 0, x...)
		if err != nil {
			t.Fatal(err)
		}

		first := x[0]
		second := x[1]

		if first.R.Audiences[0] != &a {
			t.Error("relationship was not added properly to the slice")
		}
		if second.R.Audiences[0] != &a {
			t.Error("relationship was not added properly to the slice")
		}

		if a.R.Users[i*2] != first {
			t.Error("relationship struct slice not set to correct value")
		}
		if a.R.Users[i*2+1] != second {
			t.Error("relationship struct slice not set to correct value")
		}

		count, err := a.Users().Count(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if want := int64((i + 1) * 2); count != want {
			t.Error("want", want, "got", count)
		}
	}
}

func testAudienceToManySetOpUsers(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Audience
	var b, c, d, e User

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, audienceDBTypes, false, strmangle.SetComplement(audiencePrimaryKeyColumns, audienceColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*User{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, userDBTypes, false, strmangle.SetComplement(userPrimaryKeyColumns, userColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err = a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = b.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}
	if err = c.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	err = a.SetUsers(ctx, tx, false, &b, &c)
	if err != nil {
		t.Fatal(err)
	}

	count, err := a.Users().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	err = a.SetUsers(ctx, tx, true, &d, &e)
	if err != nil {
		t.Fatal(err)
	}

	count, err = a.Users().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	// The following checks cannot be implemented since we have no handle
	// to these when we call Set(). Leaving them here as wishful thinking
	// and to let people know there's dragons.
	//
	// if len(b.R.Audiences) != 0 {
	// 	t.Error("relationship was not removed properly from the slice")
	// }
	// if len(c.R.Audiences) != 0 {
	// 	t.Error("relationship was not removed properly from the slice")
	// }
	if d.R.Audiences[0] != &a {
		t.Error("relationship was not added properly to the slice")
	}
	if e.R.Audiences[0] != &a {
		t.Error("relationship was not added properly to the slice")
	}

	if a.R.Users[0] != &d {
		t.Error("relationship struct slice not set to correct value")
	}
	if a.R.Users[1] != &e {
		t.Error("relationship struct slice not set to correct value")
	}
}

func testAudienceToManyRemoveOpUsers(t *testing.T) {
	var err error

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()

	var a Audience
	var b, c, d, e User

	seed := randomize.NewSeed()
	if err = randomize.Struct(seed, &a, audienceDBTypes, false, strmangle.SetComplement(audiencePrimaryKeyColumns, audienceColumnsWithoutDefault)...); err != nil {
		t.Fatal(err)
	}
	foreigners := []*User{&b, &c, &d, &e}
	for _, x := range foreigners {
		if err = randomize.Struct(seed, x, userDBTypes, false, strmangle.SetComplement(userPrimaryKeyColumns, userColumnsWithoutDefault)...); err != nil {
			t.Fatal(err)
		}
	}

	if err := a.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	err = a.AddUsers(ctx, tx, true, foreigners...)
	if err != nil {
		t.Fatal(err)
	}

	count, err := a.Users().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Error("count was wrong:", count)
	}

	err = a.RemoveUsers(ctx, tx, foreigners[:2]...)
	if err != nil {
		t.Fatal(err)
	}

	count, err = a.Users().Count(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Error("count was wrong:", count)
	}

	if len(b.R.Audiences) != 0 {
		t.Error("relationship was not removed properly from the slice")
	}
	if len(c.R.Audiences) != 0 {
		t.Error("relationship was not removed properly from the slice")
	}
	if d.R.Audiences[0] != &a {
		t.Error("relationship was not added properly to the foreign struct")
	}
	if e.R.Audiences[0] != &a {
		t.Error("relationship was not added properly to the foreign struct")
	}

	if len(a.R.Users) != 2 {
		t.Error("should have preserved two relationships")
	}

	// Removal doesn't do a stable deletion for performance so we have to flip the order
	if a.R.Users[1] != &d {
		t.Error("relationship to d should have been preserved")
	}
	if a.R.Users[0] != &e {
		t.Error("relationship to e should have been preserved")
	}
}

func testAudiencesReload(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	if err = o.Reload(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testAudiencesReloadAll(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice := AudienceSlice{o}

	if err = slice.ReloadAll(ctx, tx); err != nil {
		t.Error(err)
	}
}

func testAudiencesSelect(t *testing.T) {
	t.Parallel()

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	slice, err := Audiences().All(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if len(slice) != 1 {
		t.Error("want one record, got:", len(slice))
	}
}

var (
	audienceDBTypes = map[string]string{`ID`: `integer`, `CreatedAt`: `timestamp with time zone`, `UpdatedAt`: `timestamp with time zone`, `Name`: `character varying`, `Description`: `character varying`}
	_               = bytes.MinRead
)

func testAudiencesUpdate(t *testing.T) {
	t.Parallel()

	if 0 == len(audiencePrimaryKeyColumns) {
		t.Skip("Skipping table with no primary key columns")
	}
	if len(audienceAllColumns) == len(audiencePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, audienceDBTypes, true, audiencePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	if rowsAff, err := o.Update(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("should only affect one row but affected", rowsAff)
	}
}

func testAudiencesSliceUpdateAll(t *testing.T) {
	t.Parallel()

	if len(audienceAllColumns) == len(audiencePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	o := &Audience{}
	if err = randomize.Struct(seed, o, audienceDBTypes, true, audienceColumnsWithDefault...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Insert(ctx, tx, boil.Infer()); err != nil {
		t.Error(err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}

	if count != 1 {
		t.Error("want one record, got:", count)
	}

	if err = randomize.Struct(seed, o, audienceDBTypes, true, audiencePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	// Remove Primary keys and unique columns from what we plan to update
	var fields []string
	if strmangle.StringSliceMatch(audienceAllColumns, audiencePrimaryKeyColumns) {
		fields = audienceAllColumns
	} else {
		fields = strmangle.SetComplement(
			audienceAllColumns,
			audiencePrimaryKeyColumns,
		)
	}

	value := reflect.Indirect(reflect.ValueOf(o))
	typ := reflect.TypeOf(o).Elem()
	n := typ.NumField()

	updateMap := M{}
	for _, col := range fields {
		for i := 0; i < n; i++ {
			f := typ.Field(i)
			if f.Tag.Get("boil") == col {
				updateMap[col] = value.Field(i).Interface()
			}
		}
	}

	slice := AudienceSlice{o}
	if rowsAff, err := slice.UpdateAll(ctx, tx, updateMap); err != nil {
		t.Error(err)
	} else if rowsAff != 1 {
		t.Error("wanted one record updated but got", rowsAff)
	}
}

func testAudiencesUpsert(t *testing.T) {
	t.Parallel()

	if len(audienceAllColumns) == len(audiencePrimaryKeyColumns) {
		t.Skip("Skipping table with only primary key columns")
	}

	seed := randomize.NewSeed()
	var err error
	// Attempt the INSERT side of an UPSERT
	o := Audience{}
	if err = randomize.Struct(seed, &o, audienceDBTypes, true); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	ctx := context.Background()
	tx := MustTx(boil.BeginTx(ctx, nil))
	defer func() { _ = tx.Rollback() }()
	if err = o.Upsert(ctx, tx, false, nil, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Audience: %s", err)
	}

	count, err := Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}

	// Attempt the UPDATE side of an UPSERT
	if err = randomize.Struct(seed, &o, audienceDBTypes, false, audiencePrimaryKeyColumns...); err != nil {
		t.Errorf("Unable to randomize Audience struct: %s", err)
	}

	if err = o.Upsert(ctx, tx, true, nil, boil.Infer(), boil.Infer()); err != nil {
		t.Errorf("Unable to upsert Audience: %s", err)
	}

	count, err = Audiences().Count(ctx, tx)
	if err != nil {
		t.Error(err)
	}
	if count != 1 {
		t.Error("want one record, got:", count)
	}
}
