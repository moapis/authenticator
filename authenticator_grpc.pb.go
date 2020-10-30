// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package authenticator

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// AuthenticatorClient is the client API for Authenticator service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthenticatorClient interface {
	// RegisterPwUser registers a new user which can authenticate using a PW.
	// Server implementation should grant the user only a public role untill verification is complete.
	// Authorization: Public
	RegisterPwUser(ctx context.Context, in *RegistrationData, opts ...grpc.CallOption) (*RegistrationReply, error)
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
	// GetPubKey retrieves registered public keys from the database, identified by KeyIDs.
	// Authorization: Internal
	GetPubKey(ctx context.Context, in *KeyID, opts ...grpc.CallOption) (*PublicKey, error)
	// ResetUserPW sends a password reset e-mail to a registered user.
	// The e-mail will contain an URL, as per passed CallBackURL.
	// The URL will contain a token which (only) can be used for setting a new password.
	ResetUserPW(ctx context.Context, in *UserEmail, opts ...grpc.CallOption) (*empty.Empty, error)
}

type authenticatorClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthenticatorClient(cc grpc.ClientConnInterface) AuthenticatorClient {
	return &authenticatorClient{cc}
}

func (c *authenticatorClient) RegisterPwUser(ctx context.Context, in *RegistrationData, opts ...grpc.CallOption) (*RegistrationReply, error) {
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

func (c *authenticatorClient) ResetUserPW(ctx context.Context, in *UserEmail, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/authenticator.Authenticator/ResetUserPW", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticatorServer is the server API for Authenticator service.
// All implementations must embed UnimplementedAuthenticatorServer
// for forward compatibility
type AuthenticatorServer interface {
	// RegisterPwUser registers a new user which can authenticate using a PW.
	// Server implementation should grant the user only a public role untill verification is complete.
	// Authorization: Public
	RegisterPwUser(context.Context, *RegistrationData) (*RegistrationReply, error)
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
	// GetPubKey retrieves registered public keys from the database, identified by KeyIDs.
	// Authorization: Internal
	GetPubKey(context.Context, *KeyID) (*PublicKey, error)
	// ResetUserPW sends a password reset e-mail to a registered user.
	// The e-mail will contain an URL, as per passed CallBackURL.
	// The URL will contain a token which (only) can be used for setting a new password.
	ResetUserPW(context.Context, *UserEmail) (*empty.Empty, error)
	mustEmbedUnimplementedAuthenticatorServer()
}

// UnimplementedAuthenticatorServer must be embedded to have forward compatible implementations.
type UnimplementedAuthenticatorServer struct {
}

func (UnimplementedAuthenticatorServer) RegisterPwUser(context.Context, *RegistrationData) (*RegistrationReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterPwUser not implemented")
}
func (UnimplementedAuthenticatorServer) AuthenticatePwUser(context.Context, *UserPassword) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthenticatePwUser not implemented")
}
func (UnimplementedAuthenticatorServer) ChangeUserPw(context.Context, *NewUserPassword) (*ChangePwReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangeUserPw not implemented")
}
func (UnimplementedAuthenticatorServer) CheckUserExists(context.Context, *UserData) (*Exists, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckUserExists not implemented")
}
func (UnimplementedAuthenticatorServer) VerifyUser(context.Context, *AuthReply) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyUser not implemented")
}
func (UnimplementedAuthenticatorServer) RefreshToken(context.Context, *AuthReply) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedAuthenticatorServer) PublicUserToken(context.Context, *PublicUser) (*AuthReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PublicUserToken not implemented")
}
func (UnimplementedAuthenticatorServer) GetPubKey(context.Context, *KeyID) (*PublicKey, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPubKey not implemented")
}
func (UnimplementedAuthenticatorServer) ResetUserPW(context.Context, *UserEmail) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetUserPW not implemented")
}
func (UnimplementedAuthenticatorServer) mustEmbedUnimplementedAuthenticatorServer() {}

// UnsafeAuthenticatorServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthenticatorServer will
// result in compilation errors.
type UnsafeAuthenticatorServer interface {
	mustEmbedUnimplementedAuthenticatorServer()
}

func RegisterAuthenticatorServer(s grpc.ServiceRegistrar, srv AuthenticatorServer) {
	s.RegisterService(&_Authenticator_serviceDesc, srv)
}

func _Authenticator_RegisterPwUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegistrationData)
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
		return srv.(AuthenticatorServer).RegisterPwUser(ctx, req.(*RegistrationData))
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

func _Authenticator_ResetUserPW_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserEmail)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticatorServer).ResetUserPW(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authenticator.Authenticator/ResetUserPW",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticatorServer).ResetUserPW(ctx, req.(*UserEmail))
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
		{
			MethodName: "ResetUserPW",
			Handler:    _Authenticator_ResetUserPW_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authenticator.proto",
}
