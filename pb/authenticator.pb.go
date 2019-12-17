// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pb/authenticator.proto

package authenticator

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type UserLevels int32

const (
	UserLevels_PUBLIC  UserLevels = 0
	UserLevels_USER    UserLevels = 1
	UserLevels_EDITOR  UserLevels = 2
	UserLevels_MANAGER UserLevels = 3
	UserLevels_ADMIN   UserLevels = 4
)

var UserLevels_name = map[int32]string{
	0: "PUBLIC",
	1: "USER",
	2: "EDITOR",
	3: "MANAGER",
	4: "ADMIN",
}

var UserLevels_value = map[string]int32{
	"PUBLIC":  0,
	"USER":    1,
	"EDITOR":  2,
	"MANAGER": 3,
	"ADMIN":   4,
}

func (x UserLevels) String() string {
	return proto.EnumName(UserLevels_name, int32(x))
}

func (UserLevels) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{0}
}

type UserData struct {
	Email                string   `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Name                 string   `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UserData) Reset()         { *m = UserData{} }
func (m *UserData) String() string { return proto.CompactTextString(m) }
func (*UserData) ProtoMessage()    {}
func (*UserData) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{0}
}

func (m *UserData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UserData.Unmarshal(m, b)
}
func (m *UserData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UserData.Marshal(b, m, deterministic)
}
func (m *UserData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserData.Merge(m, src)
}
func (m *UserData) XXX_Size() int {
	return xxx_messageInfo_UserData.Size(m)
}
func (m *UserData) XXX_DiscardUnknown() {
	xxx_messageInfo_UserData.DiscardUnknown(m)
}

var xxx_messageInfo_UserData proto.InternalMessageInfo

func (m *UserData) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *UserData) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type RegistrationReply struct {
	UserId               int32    `protobuf:"varint,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RegistrationReply) Reset()         { *m = RegistrationReply{} }
func (m *RegistrationReply) String() string { return proto.CompactTextString(m) }
func (*RegistrationReply) ProtoMessage()    {}
func (*RegistrationReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{1}
}

func (m *RegistrationReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RegistrationReply.Unmarshal(m, b)
}
func (m *RegistrationReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RegistrationReply.Marshal(b, m, deterministic)
}
func (m *RegistrationReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RegistrationReply.Merge(m, src)
}
func (m *RegistrationReply) XXX_Size() int {
	return xxx_messageInfo_RegistrationReply.Size(m)
}
func (m *RegistrationReply) XXX_DiscardUnknown() {
	xxx_messageInfo_RegistrationReply.DiscardUnknown(m)
}

var xxx_messageInfo_RegistrationReply proto.InternalMessageInfo

func (m *RegistrationReply) GetUserId() int32 {
	if m != nil {
		return m.UserId
	}
	return 0
}

type AuthReply struct {
	// JSON Web Token
	Jwt                  string   `protobuf:"bytes,1,opt,name=jwt,proto3" json:"jwt,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AuthReply) Reset()         { *m = AuthReply{} }
func (m *AuthReply) String() string { return proto.CompactTextString(m) }
func (*AuthReply) ProtoMessage()    {}
func (*AuthReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{2}
}

func (m *AuthReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AuthReply.Unmarshal(m, b)
}
func (m *AuthReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AuthReply.Marshal(b, m, deterministic)
}
func (m *AuthReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuthReply.Merge(m, src)
}
func (m *AuthReply) XXX_Size() int {
	return xxx_messageInfo_AuthReply.Size(m)
}
func (m *AuthReply) XXX_DiscardUnknown() {
	xxx_messageInfo_AuthReply.DiscardUnknown(m)
}

var xxx_messageInfo_AuthReply proto.InternalMessageInfo

func (m *AuthReply) GetJwt() string {
	if m != nil {
		return m.Jwt
	}
	return ""
}

// UserPassword holds the name or e-mail of the user and its password.
type UserPassword struct {
	// Types that are valid to be assigned to User:
	//	*UserPassword_Email
	//	*UserPassword_Name
	User                 isUserPassword_User `protobuf_oneof:"user"`
	Password             string              `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *UserPassword) Reset()         { *m = UserPassword{} }
func (m *UserPassword) String() string { return proto.CompactTextString(m) }
func (*UserPassword) ProtoMessage()    {}
func (*UserPassword) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{3}
}

func (m *UserPassword) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UserPassword.Unmarshal(m, b)
}
func (m *UserPassword) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UserPassword.Marshal(b, m, deterministic)
}
func (m *UserPassword) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UserPassword.Merge(m, src)
}
func (m *UserPassword) XXX_Size() int {
	return xxx_messageInfo_UserPassword.Size(m)
}
func (m *UserPassword) XXX_DiscardUnknown() {
	xxx_messageInfo_UserPassword.DiscardUnknown(m)
}

var xxx_messageInfo_UserPassword proto.InternalMessageInfo

type isUserPassword_User interface {
	isUserPassword_User()
}

type UserPassword_Email struct {
	Email string `protobuf:"bytes,1,opt,name=email,proto3,oneof"`
}

type UserPassword_Name struct {
	Name string `protobuf:"bytes,2,opt,name=name,proto3,oneof"`
}

func (*UserPassword_Email) isUserPassword_User() {}

func (*UserPassword_Name) isUserPassword_User() {}

func (m *UserPassword) GetUser() isUserPassword_User {
	if m != nil {
		return m.User
	}
	return nil
}

func (m *UserPassword) GetEmail() string {
	if x, ok := m.GetUser().(*UserPassword_Email); ok {
		return x.Email
	}
	return ""
}

func (m *UserPassword) GetName() string {
	if x, ok := m.GetUser().(*UserPassword_Name); ok {
		return x.Name
	}
	return ""
}

func (m *UserPassword) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*UserPassword) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*UserPassword_Email)(nil),
		(*UserPassword_Name)(nil),
	}
}

type NewUserPassword struct {
	// Types that are valid to be assigned to User:
	//	*NewUserPassword_Email
	//	*NewUserPassword_Name
	User isNewUserPassword_User `protobuf_oneof:"user"`
	// Types that are valid to be assigned to Credential:
	//	*NewUserPassword_OldPassword
	//	*NewUserPassword_ResetToken
	Credential           isNewUserPassword_Credential `protobuf_oneof:"credential"`
	NewPassword          string                       `protobuf:"bytes,5,opt,name=new_password,json=newPassword,proto3" json:"new_password,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *NewUserPassword) Reset()         { *m = NewUserPassword{} }
func (m *NewUserPassword) String() string { return proto.CompactTextString(m) }
func (*NewUserPassword) ProtoMessage()    {}
func (*NewUserPassword) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{4}
}

func (m *NewUserPassword) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NewUserPassword.Unmarshal(m, b)
}
func (m *NewUserPassword) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NewUserPassword.Marshal(b, m, deterministic)
}
func (m *NewUserPassword) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NewUserPassword.Merge(m, src)
}
func (m *NewUserPassword) XXX_Size() int {
	return xxx_messageInfo_NewUserPassword.Size(m)
}
func (m *NewUserPassword) XXX_DiscardUnknown() {
	xxx_messageInfo_NewUserPassword.DiscardUnknown(m)
}

var xxx_messageInfo_NewUserPassword proto.InternalMessageInfo

type isNewUserPassword_User interface {
	isNewUserPassword_User()
}

type NewUserPassword_Email struct {
	Email string `protobuf:"bytes,1,opt,name=email,proto3,oneof"`
}

type NewUserPassword_Name struct {
	Name string `protobuf:"bytes,2,opt,name=name,proto3,oneof"`
}

func (*NewUserPassword_Email) isNewUserPassword_User() {}

func (*NewUserPassword_Name) isNewUserPassword_User() {}

func (m *NewUserPassword) GetUser() isNewUserPassword_User {
	if m != nil {
		return m.User
	}
	return nil
}

func (m *NewUserPassword) GetEmail() string {
	if x, ok := m.GetUser().(*NewUserPassword_Email); ok {
		return x.Email
	}
	return ""
}

func (m *NewUserPassword) GetName() string {
	if x, ok := m.GetUser().(*NewUserPassword_Name); ok {
		return x.Name
	}
	return ""
}

type isNewUserPassword_Credential interface {
	isNewUserPassword_Credential()
}

type NewUserPassword_OldPassword struct {
	OldPassword string `protobuf:"bytes,3,opt,name=old_password,json=oldPassword,proto3,oneof"`
}

type NewUserPassword_ResetToken struct {
	ResetToken string `protobuf:"bytes,4,opt,name=reset_token,json=resetToken,proto3,oneof"`
}

func (*NewUserPassword_OldPassword) isNewUserPassword_Credential() {}

func (*NewUserPassword_ResetToken) isNewUserPassword_Credential() {}

func (m *NewUserPassword) GetCredential() isNewUserPassword_Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (m *NewUserPassword) GetOldPassword() string {
	if x, ok := m.GetCredential().(*NewUserPassword_OldPassword); ok {
		return x.OldPassword
	}
	return ""
}

func (m *NewUserPassword) GetResetToken() string {
	if x, ok := m.GetCredential().(*NewUserPassword_ResetToken); ok {
		return x.ResetToken
	}
	return ""
}

func (m *NewUserPassword) GetNewPassword() string {
	if m != nil {
		return m.NewPassword
	}
	return ""
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*NewUserPassword) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*NewUserPassword_Email)(nil),
		(*NewUserPassword_Name)(nil),
		(*NewUserPassword_OldPassword)(nil),
		(*NewUserPassword_ResetToken)(nil),
	}
}

type ChangePwReply struct {
	Success              bool     `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ChangePwReply) Reset()         { *m = ChangePwReply{} }
func (m *ChangePwReply) String() string { return proto.CompactTextString(m) }
func (*ChangePwReply) ProtoMessage()    {}
func (*ChangePwReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{5}
}

func (m *ChangePwReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChangePwReply.Unmarshal(m, b)
}
func (m *ChangePwReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChangePwReply.Marshal(b, m, deterministic)
}
func (m *ChangePwReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChangePwReply.Merge(m, src)
}
func (m *ChangePwReply) XXX_Size() int {
	return xxx_messageInfo_ChangePwReply.Size(m)
}
func (m *ChangePwReply) XXX_DiscardUnknown() {
	xxx_messageInfo_ChangePwReply.DiscardUnknown(m)
}

var xxx_messageInfo_ChangePwReply proto.InternalMessageInfo

func (m *ChangePwReply) GetSuccess() bool {
	if m != nil {
		return m.Success
	}
	return false
}

type Exists struct {
	Email                bool     `protobuf:"varint,1,opt,name=email,proto3" json:"email,omitempty"`
	Name                 bool     `protobuf:"varint,2,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Exists) Reset()         { *m = Exists{} }
func (m *Exists) String() string { return proto.CompactTextString(m) }
func (*Exists) ProtoMessage()    {}
func (*Exists) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{6}
}

func (m *Exists) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Exists.Unmarshal(m, b)
}
func (m *Exists) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Exists.Marshal(b, m, deterministic)
}
func (m *Exists) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Exists.Merge(m, src)
}
func (m *Exists) XXX_Size() int {
	return xxx_messageInfo_Exists.Size(m)
}
func (m *Exists) XXX_DiscardUnknown() {
	xxx_messageInfo_Exists.DiscardUnknown(m)
}

var xxx_messageInfo_Exists proto.InternalMessageInfo

func (m *Exists) GetEmail() bool {
	if m != nil {
		return m.Email
	}
	return false
}

func (m *Exists) GetName() bool {
	if m != nil {
		return m.Name
	}
	return false
}

type PublicUser struct {
	Uuid                 string   `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PublicUser) Reset()         { *m = PublicUser{} }
func (m *PublicUser) String() string { return proto.CompactTextString(m) }
func (*PublicUser) ProtoMessage()    {}
func (*PublicUser) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{7}
}

func (m *PublicUser) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicUser.Unmarshal(m, b)
}
func (m *PublicUser) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicUser.Marshal(b, m, deterministic)
}
func (m *PublicUser) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicUser.Merge(m, src)
}
func (m *PublicUser) XXX_Size() int {
	return xxx_messageInfo_PublicUser.Size(m)
}
func (m *PublicUser) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicUser.DiscardUnknown(m)
}

var xxx_messageInfo_PublicUser proto.InternalMessageInfo

func (m *PublicUser) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

type KeyID struct {
	Kid                  int32    `protobuf:"varint,1,opt,name=kid,proto3" json:"kid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeyID) Reset()         { *m = KeyID{} }
func (m *KeyID) String() string { return proto.CompactTextString(m) }
func (*KeyID) ProtoMessage()    {}
func (*KeyID) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{8}
}

func (m *KeyID) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyID.Unmarshal(m, b)
}
func (m *KeyID) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyID.Marshal(b, m, deterministic)
}
func (m *KeyID) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyID.Merge(m, src)
}
func (m *KeyID) XXX_Size() int {
	return xxx_messageInfo_KeyID.Size(m)
}
func (m *KeyID) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyID.DiscardUnknown(m)
}

var xxx_messageInfo_KeyID proto.InternalMessageInfo

func (m *KeyID) GetKid() int32 {
	if m != nil {
		return m.Kid
	}
	return 0
}

type PublicKey struct {
	Key                  []byte   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PublicKey) Reset()         { *m = PublicKey{} }
func (m *PublicKey) String() string { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()    {}
func (*PublicKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_8ea890b446739740, []int{9}
}

func (m *PublicKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicKey.Unmarshal(m, b)
}
func (m *PublicKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicKey.Marshal(b, m, deterministic)
}
func (m *PublicKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKey.Merge(m, src)
}
func (m *PublicKey) XXX_Size() int {
	return xxx_messageInfo_PublicKey.Size(m)
}
func (m *PublicKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKey.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKey proto.InternalMessageInfo

func (m *PublicKey) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func init() {
	proto.RegisterEnum("authenticator.UserLevels", UserLevels_name, UserLevels_value)
	proto.RegisterType((*UserData)(nil), "authenticator.UserData")
	proto.RegisterType((*RegistrationReply)(nil), "authenticator.RegistrationReply")
	proto.RegisterType((*AuthReply)(nil), "authenticator.AuthReply")
	proto.RegisterType((*UserPassword)(nil), "authenticator.UserPassword")
	proto.RegisterType((*NewUserPassword)(nil), "authenticator.NewUserPassword")
	proto.RegisterType((*ChangePwReply)(nil), "authenticator.ChangePwReply")
	proto.RegisterType((*Exists)(nil), "authenticator.Exists")
	proto.RegisterType((*PublicUser)(nil), "authenticator.PublicUser")
	proto.RegisterType((*KeyID)(nil), "authenticator.KeyID")
	proto.RegisterType((*PublicKey)(nil), "authenticator.PublicKey")
}

func init() { proto.RegisterFile("pb/authenticator.proto", fileDescriptor_8ea890b446739740) }

var fileDescriptor_8ea890b446739740 = []byte{
	// 591 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x54, 0x4b, 0x4f, 0xdb, 0x4c,
	0x14, 0x75, 0x20, 0x09, 0xce, 0x8d, 0xf9, 0xf0, 0x37, 0xa2, 0x60, 0xd2, 0x87, 0x60, 0xba, 0x69,
	0xab, 0x8a, 0x4a, 0xb4, 0xdb, 0x2e, 0xf2, 0x2a, 0x89, 0x20, 0xa9, 0x35, 0x85, 0x6e, 0xa9, 0x63,
	0x5f, 0x88, 0x1b, 0x63, 0x47, 0x9e, 0x71, 0xdd, 0xfc, 0xbb, 0xfe, 0x89, 0xfe, 0x9f, 0x6a, 0xc6,
	0x4e, 0xc0, 0xe6, 0xb1, 0x68, 0x77, 0xf7, 0x79, 0xe6, 0x5c, 0x9f, 0x23, 0xc3, 0xce, 0x7c, 0xf2,
	0xce, 0x49, 0xc4, 0x14, 0x43, 0xe1, 0xbb, 0x8e, 0x88, 0xe2, 0xc3, 0x79, 0x1c, 0x89, 0x88, 0x6c,
	0x16, 0x8a, 0xf4, 0x03, 0xe8, 0xe7, 0x1c, 0xe3, 0x9e, 0x23, 0x1c, 0xb2, 0x0d, 0x35, 0xbc, 0x76,
	0xfc, 0xc0, 0xaa, 0xec, 0x57, 0x5e, 0x35, 0x58, 0x96, 0x10, 0x02, 0xd5, 0xd0, 0xb9, 0x46, 0x6b,
	0x4d, 0x15, 0x55, 0x4c, 0xdf, 0xc2, 0xff, 0x0c, 0xaf, 0x7c, 0x2e, 0x62, 0x47, 0xf8, 0x51, 0xc8,
	0x70, 0x1e, 0x2c, 0xc8, 0x2e, 0x6c, 0x24, 0x1c, 0xe3, 0x0b, 0xdf, 0x53, 0x00, 0x35, 0x56, 0x97,
	0xe9, 0xd0, 0xa3, 0xcf, 0xa1, 0xd1, 0x4e, 0xc4, 0x34, 0x9b, 0x32, 0x61, 0xfd, 0x7b, 0x2a, 0xf2,
	0x27, 0x64, 0x48, 0xbf, 0x81, 0x21, 0x29, 0xd8, 0x0e, 0xe7, 0x69, 0x14, 0x7b, 0x64, 0xa7, 0x40,
	0x63, 0xa0, 0x2d, 0x89, 0x6c, 0xdf, 0x26, 0x32, 0xd0, 0x32, 0x2a, 0xa4, 0x05, 0xfa, 0x3c, 0xdf,
	0xb4, 0xd6, 0x15, 0xe8, 0x2a, 0xef, 0xd4, 0xa1, 0x2a, 0x29, 0xd0, 0x5f, 0x15, 0xd8, 0x1a, 0x63,
	0xfa, 0x0f, 0xaf, 0xbc, 0x04, 0x23, 0x0a, 0xbc, 0x8b, 0xe2, 0x4b, 0x83, 0x0a, 0x6b, 0x46, 0x81,
	0xb7, 0x82, 0x3c, 0x80, 0x66, 0x8c, 0x1c, 0xc5, 0x85, 0x88, 0x66, 0x18, 0x5a, 0xd5, 0x7c, 0x06,
	0x54, 0xf1, 0x4c, 0xd6, 0xc8, 0x01, 0x18, 0x21, 0xa6, 0x37, 0x38, 0x35, 0xc5, 0xb8, 0x19, 0x62,
	0x6a, 0x97, 0x48, 0x77, 0x0c, 0x00, 0x37, 0x46, 0x4f, 0x4a, 0xe5, 0x04, 0xf4, 0x35, 0x6c, 0x76,
	0xa7, 0x4e, 0x78, 0x85, 0x76, 0x9a, 0x7d, 0x47, 0x0b, 0x36, 0x78, 0xe2, 0xba, 0xc8, 0xb9, 0xba,
	0x40, 0x67, 0xcb, 0x94, 0x1e, 0x41, 0xbd, 0xff, 0xd3, 0xe7, 0x82, 0x17, 0x05, 0xd5, 0xef, 0x13,
	0x54, 0xcf, 0x05, 0xdd, 0x07, 0xb0, 0x93, 0x49, 0xe0, 0xbb, 0xf2, 0x1b, 0xc9, 0x89, 0x24, 0xc9,
	0x65, 0x6c, 0x30, 0x15, 0xd3, 0x3d, 0xa8, 0x9d, 0xe0, 0x62, 0xd8, 0x93, 0x02, 0xce, 0x56, 0x12,
	0xcb, 0x50, 0xea, 0x9b, 0x2d, 0x9f, 0xa0, 0xd2, 0x77, 0x86, 0x0b, 0xd5, 0x36, 0x98, 0x0c, 0xdf,
	0x7c, 0x02, 0x90, 0xa8, 0xa7, 0xf8, 0x03, 0x03, 0x4e, 0x00, 0xea, 0xf6, 0x79, 0xe7, 0x74, 0xd8,
	0x35, 0x35, 0xa2, 0x43, 0xf5, 0xfc, 0x4b, 0x9f, 0x99, 0x15, 0x59, 0xed, 0xf7, 0x86, 0x67, 0x9f,
	0x99, 0xb9, 0x46, 0x9a, 0xb0, 0x31, 0x6a, 0x8f, 0xdb, 0xc7, 0x7d, 0x66, 0xae, 0x93, 0x06, 0xd4,
	0xda, 0xbd, 0xd1, 0x70, 0x6c, 0x56, 0x8f, 0x7e, 0x57, 0x61, 0xb3, 0x7d, 0xdb, 0xbc, 0x64, 0x04,
	0xff, 0x65, 0x36, 0xc4, 0xd8, 0x56, 0xea, 0x92, 0xdd, 0xc3, 0xa2, 0xe7, 0x97, 0xde, 0x6e, 0xed,
	0x97, 0x1a, 0x77, 0xec, 0x4b, 0x35, 0x32, 0x02, 0x72, 0x0b, 0x1f, 0x73, 0xc8, 0xa7, 0xf7, 0x40,
	0x2e, 0xc5, 0x6a, 0x59, 0xa5, 0xe6, 0xca, 0xe7, 0x54, 0x23, 0x63, 0x30, 0x32, 0xc9, 0xd4, 0x46,
	0x4a, 0x5e, 0x94, 0x66, 0x4b, 0x8e, 0x6c, 0x3d, 0x2b, 0xf5, 0x0b, 0x7a, 0x53, 0x8d, 0x74, 0x61,
	0xab, 0x3b, 0x45, 0x77, 0x26, 0x97, 0x72, 0x81, 0x1f, 0x3c, 0xf7, 0x49, 0xa9, 0x91, 0xcd, 0x53,
	0x8d, 0x74, 0x00, 0xbe, 0x62, 0xec, 0x5f, 0x2e, 0xd4, 0x6d, 0x0f, 0xd2, 0x7f, 0xf4, 0xb0, 0x1e,
	0x18, 0x0c, 0x2f, 0x63, 0xe4, 0xd3, 0xcc, 0xd4, 0x7f, 0x87, 0x32, 0x80, 0xad, 0x1b, 0xcb, 0x65,
	0x40, 0x7b, 0xa5, 0xf1, 0x9b, 0xfe, 0xa3, 0x48, 0x1f, 0xa1, 0x71, 0x8c, 0xc2, 0x4e, 0x26, 0xd2,
	0x7f, 0xdb, 0xa5, 0x41, 0x65, 0xda, 0x3b, 0xeb, 0x2b, 0xbf, 0x52, 0x6d, 0x52, 0x57, 0x3f, 0xc6,
	0xf7, 0x7f, 0x02, 0x00, 0x00, 0xff, 0xff, 0x47, 0x48, 0xba, 0x97, 0x32, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthenticatorClient is the client API for Authenticator service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthenticatorClient interface {
	// RegisterPwUser registers a new user which can authenticate using a PW.
	// Server implementation should grant the user only a public role untill verification is complete.
	// Authorization: Public
	RegisterPwUser(ctx context.Context, in *UserData, opts ...grpc.CallOption) (*RegistrationReply, error)
	// PasswordAuth authenticates the user by its registered email or username and password.
	// Authorization: Public
	AuthenticatePwUser(ctx context.Context, in *UserPassword, opts ...grpc.CallOption) (*AuthReply, error)
	// ChangeUserPw changes the password for the user. It needs either the old password or a password reset token.
	// Authorization: Public
	ChangeUserPw(ctx context.Context, in *NewUserPassword, opts ...grpc.CallOption) (*ChangePwReply, error)
	// CheckUserExists returns true for the UserID fields which already exists.
	// Authorization: Basic
	CheckUserExists(ctx context.Context, in *UserData, opts ...grpc.CallOption) (*Exists, error)
	// VerifyUser by previously transmitted (email) verification token
	// Authorization: Public
	VerifyUser(ctx context.Context, in *AuthReply, opts ...grpc.CallOption) (*AuthReply, error)
	// RefreshToken using an old (and valid!) token.
	// The user id and its authorization level are verified against the database.
	// Authorization: Public
	RefreshToken(ctx context.Context, in *AuthReply, opts ...grpc.CallOption) (*AuthReply, error)
	// PublicUserToken generates a token for public and unauthenticated users.
	// Such token can be used for API access and session tracking.
	// Authorization: Internal
	PublicUserToken(ctx context.Context, in *PublicUser, opts ...grpc.CallOption) (*AuthReply, error)
	// GetPubKeys retrieves registered public keys from the database, identified by KeyIDs.
	// Authorization: Internal
	GetPubKey(ctx context.Context, in *KeyID, opts ...grpc.CallOption) (*PublicKey, error)
}

type authenticatorClient struct {
	cc *grpc.ClientConn
}

func NewAuthenticatorClient(cc *grpc.ClientConn) AuthenticatorClient {
	return &authenticatorClient{cc}
}

func (c *authenticatorClient) RegisterPwUser(ctx context.Context, in *UserData, opts ...grpc.CallOption) (*RegistrationReply, error) {
	out := new(RegistrationReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/RegisterPwUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) AuthenticatePwUser(ctx context.Context, in *UserPassword, opts ...grpc.CallOption) (*AuthReply, error) {
	out := new(AuthReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/AuthenticatePwUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) ChangeUserPw(ctx context.Context, in *NewUserPassword, opts ...grpc.CallOption) (*ChangePwReply, error) {
	out := new(ChangePwReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/ChangeUserPw", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) CheckUserExists(ctx context.Context, in *UserData, opts ...grpc.CallOption) (*Exists, error) {
	out := new(Exists)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/CheckUserExists", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) VerifyUser(ctx context.Context, in *AuthReply, opts ...grpc.CallOption) (*AuthReply, error) {
	out := new(AuthReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/VerifyUser", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) RefreshToken(ctx context.Context, in *AuthReply, opts ...grpc.CallOption) (*AuthReply, error) {
	out := new(AuthReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/RefreshToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) PublicUserToken(ctx context.Context, in *PublicUser, opts ...grpc.CallOption) (*AuthReply, error) {
	out := new(AuthReply)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/PublicUserToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticatorClient) GetPubKey(ctx context.Context, in *KeyID, opts ...grpc.CallOption) (*PublicKey, error) {
	out := new(PublicKey)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/GetPubKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticatorServer is the server API for Authenticator service.
type AuthenticatorServer interface {
	// RegisterPwUser registers a new user which can authenticate using a PW.
	// Server implementation should grant the user only a public role untill verification is complete.
	// Authorization: Public
	RegisterPwUser(context.Context, *UserData) (*RegistrationReply, error)
	// PasswordAuth authenticates the user by its registered email or username and password.
	// Authorization: Public
	AuthenticatePwUser(context.Context, *UserPassword) (*AuthReply, error)
	// ChangeUserPw changes the password for the user. It needs either the old password or a password reset token.
	// Authorization: Public
	ChangeUserPw(context.Context, *NewUserPassword) (*ChangePwReply, error)
	// CheckUserExists returns true for the UserID fields which already exists.
	// Authorization: Basic
	CheckUserExists(context.Context, *UserData) (*Exists, error)
	// VerifyUser by previously transmitted (email) verification token
	// Authorization: Public
	VerifyUser(context.Context, *AuthReply) (*AuthReply, error)
	// RefreshToken using an old (and valid!) token.
	// The user id and its authorization level are verified against the database.
	// Authorization: Public
	RefreshToken(context.Context, *AuthReply) (*AuthReply, error)
	// PublicUserToken generates a token for public and unauthenticated users.
	// Such token can be used for API access and session tracking.
	// Authorization: Internal
	PublicUserToken(context.Context, *PublicUser) (*AuthReply, error)
	// GetPubKeys retrieves registered public keys from the database, identified by KeyIDs.
	// Authorization: Internal
	GetPubKey(context.Context, *KeyID) (*PublicKey, error)
}

// UnimplementedAuthenticatorServer can be embedded to have forward compatible implementations.
type UnimplementedAuthenticatorServer struct {
}

func (*UnimplementedAuthenticatorServer) RegisterPwUser(ctx context.Context, req *UserData) (*RegistrationReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterPwUser not implemented")
}
func (*UnimplementedAuthenticatorServer) AuthenticatePwUser(ctx context.Context, req *UserPassword) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthenticatePwUser not implemented")
}
func (*UnimplementedAuthenticatorServer) ChangeUserPw(ctx context.Context, req *NewUserPassword) (*ChangePwReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangeUserPw not implemented")
}
func (*UnimplementedAuthenticatorServer) CheckUserExists(ctx context.Context, req *UserData) (*Exists, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckUserExists not implemented")
}
func (*UnimplementedAuthenticatorServer) VerifyUser(ctx context.Context, req *AuthReply) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyUser not implemented")
}
func (*UnimplementedAuthenticatorServer) RefreshToken(ctx context.Context, req *AuthReply) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (*UnimplementedAuthenticatorServer) PublicUserToken(ctx context.Context, req *PublicUser) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PublicUserToken not implemented")
}
func (*UnimplementedAuthenticatorServer) GetPubKey(ctx context.Context, req *KeyID) (*PublicKey, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPubKey not implemented")
}

func RegisterAuthenticatorServer(s *grpc.Server, srv AuthenticatorServer) {
	s.RegisterService(&_Authenticator_serviceDesc, srv)
}

func _Authenticator_RegisterPwUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserData)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).RegisterPwUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/RegisterPwUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).RegisterPwUser(ctx, req.(*UserData))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_AuthenticatePwUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserPassword)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).AuthenticatePwUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/AuthenticatePwUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).AuthenticatePwUser(ctx, req.(*UserPassword))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_ChangeUserPw_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewUserPassword)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).ChangeUserPw(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/ChangeUserPw",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).ChangeUserPw(ctx, req.(*NewUserPassword))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_CheckUserExists_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserData)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).CheckUserExists(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/CheckUserExists",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).CheckUserExists(ctx, req.(*UserData))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_VerifyUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthReply)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).VerifyUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/VerifyUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).VerifyUser(ctx, req.(*AuthReply))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthReply)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/RefreshToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).RefreshToken(ctx, req.(*AuthReply))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_PublicUserToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicUser)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).PublicUserToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/PublicUserToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).PublicUserToken(ctx, req.(*PublicUser))
	}
	return interceptor(ctx, in, info, handler)
}

func _Authenticator_GetPubKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KeyID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).GetPubKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/GetPubKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).GetPubKey(ctx, req.(*KeyID))
	}
	return interceptor(ctx, in, info, handler)
}

var _Authenticator_serviceDesc = grpc.ServiceDesc{
	ServiceName: "authenticator.Authenticator",
	HandlerType: (*AuthenticatorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RegisterPwUser",
			Handler:    _Authenticator_RegisterPwUser_Handler,
		},
		{
			MethodName: "AuthenticatePwUser",
			Handler:    _Authenticator_AuthenticatePwUser_Handler,
		},
		{
			MethodName: "ChangeUserPw",
			Handler:    _Authenticator_ChangeUserPw_Handler,
		},
		{
			MethodName: "CheckUserExists",
			Handler:    _Authenticator_CheckUserExists_Handler,
		},
		{
			MethodName: "VerifyUser",
			Handler:    _Authenticator_VerifyUser_Handler,
		},
		{
			MethodName: "RefreshToken",
			Handler:    _Authenticator_RefreshToken_Handler,
		},
		{
			MethodName: "PublicUserToken",
			Handler:    _Authenticator_PublicUserToken_Handler,
		},
		{
			MethodName: "GetPubKey",
			Handler:    _Authenticator_GetPubKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pb/authenticator.proto",
}
