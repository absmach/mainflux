// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.2
// source: things/v1/things.proto

package v1

import (
	v1 "github.com/absmach/magistrala/internal/grpc/common/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AuthzReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelId  string `protobuf:"bytes,1,opt,name=channel_id,json=channelId,proto3" json:"channel_id,omitempty"`
	ThingId    string `protobuf:"bytes,2,opt,name=thing_id,json=thingId,proto3" json:"thing_id,omitempty"`
	ThingKey   string `protobuf:"bytes,3,opt,name=thing_key,json=thingKey,proto3" json:"thing_key,omitempty"`
	Permission string `protobuf:"bytes,4,opt,name=permission,proto3" json:"permission,omitempty"`
}

func (x *AuthzReq) Reset() {
	*x = AuthzReq{}
	mi := &file_things_v1_things_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthzReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthzReq) ProtoMessage() {}

func (x *AuthzReq) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthzReq.ProtoReflect.Descriptor instead.
func (*AuthzReq) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{0}
}

func (x *AuthzReq) GetChannelId() string {
	if x != nil {
		return x.ChannelId
	}
	return ""
}

func (x *AuthzReq) GetThingId() string {
	if x != nil {
		return x.ThingId
	}
	return ""
}

func (x *AuthzReq) GetThingKey() string {
	if x != nil {
		return x.ThingKey
	}
	return ""
}

func (x *AuthzReq) GetPermission() string {
	if x != nil {
		return x.Permission
	}
	return ""
}

type AuthzRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Authorized bool   `protobuf:"varint,1,opt,name=authorized,proto3" json:"authorized,omitempty"`
	Id         string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *AuthzRes) Reset() {
	*x = AuthzRes{}
	mi := &file_things_v1_things_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthzRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthzRes) ProtoMessage() {}

func (x *AuthzRes) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthzRes.ProtoReflect.Descriptor instead.
func (*AuthzRes) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{1}
}

func (x *AuthzRes) GetAuthorized() bool {
	if x != nil {
		return x.Authorized
	}
	return false
}

func (x *AuthzRes) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

var File_things_v1_things_proto protoreflect.FileDescriptor

var file_things_v1_things_proto_rawDesc = []byte{
	0x0a, 0x16, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x68, 0x69, 0x6e,
	0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x81, 0x01, 0x0a, 0x08,
	0x41, 0x75, 0x74, 0x68, 0x7a, 0x52, 0x65, 0x71, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x68,
	0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x68, 0x69, 0x6e, 0x67,
	0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x74, 0x68, 0x69, 0x6e, 0x67,
	0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x12,
	0x1e, 0x0a, 0x0a, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x22,
	0x3a, 0x0a, 0x08, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x52, 0x65, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x32, 0x97, 0x03, 0x0a, 0x0d,
	0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x37, 0x0a,
	0x09, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x13, 0x2e, 0x74, 0x68, 0x69,
	0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x7a, 0x52, 0x65, 0x71, 0x1a,
	0x13, 0x2e, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x7a, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x4e, 0x0a, 0x0e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65,
	0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x1c, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x1c, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x54, 0x0a, 0x10, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65,
	0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x12, 0x1e, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x1e, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x4e, 0x0a, 0x0e,
	0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1c,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x1c, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x57, 0x0a, 0x11,
	0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x1f, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65,
	0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x71, 0x1a, 0x1f, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52,
	0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x65, 0x73, 0x22, 0x00, 0x42, 0x37, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x62, 0x73, 0x6d, 0x61, 0x63, 0x68, 0x2f, 0x6d, 0x61, 0x67, 0x69,
	0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_things_v1_things_proto_rawDescOnce sync.Once
	file_things_v1_things_proto_rawDescData = file_things_v1_things_proto_rawDesc
)

func file_things_v1_things_proto_rawDescGZIP() []byte {
	file_things_v1_things_proto_rawDescOnce.Do(func() {
		file_things_v1_things_proto_rawDescData = protoimpl.X.CompressGZIP(file_things_v1_things_proto_rawDescData)
	})
	return file_things_v1_things_proto_rawDescData
}

var file_things_v1_things_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_things_v1_things_proto_goTypes = []any{
	(*AuthzReq)(nil),                // 0: things.v1.AuthzReq
	(*AuthzRes)(nil),                // 1: things.v1.AuthzRes
	(*v1.RetrieveEntityReq)(nil),    // 2: common.v1.RetrieveEntityReq
	(*v1.RetrieveEntitiesReq)(nil),  // 3: common.v1.RetrieveEntitiesReq
	(*v1.AddConnectionsReq)(nil),    // 4: common.v1.AddConnectionsReq
	(*v1.RemoveConnectionsReq)(nil), // 5: common.v1.RemoveConnectionsReq
	(*v1.RetrieveEntityRes)(nil),    // 6: common.v1.RetrieveEntityRes
	(*v1.RetrieveEntitiesRes)(nil),  // 7: common.v1.RetrieveEntitiesRes
	(*v1.AddConnectionsRes)(nil),    // 8: common.v1.AddConnectionsRes
	(*v1.RemoveConnectionsRes)(nil), // 9: common.v1.RemoveConnectionsRes
}
var file_things_v1_things_proto_depIdxs = []int32{
	0, // 0: things.v1.ThingsService.Authorize:input_type -> things.v1.AuthzReq
	2, // 1: things.v1.ThingsService.RetrieveEntity:input_type -> common.v1.RetrieveEntityReq
	3, // 2: things.v1.ThingsService.RetrieveEntities:input_type -> common.v1.RetrieveEntitiesReq
	4, // 3: things.v1.ThingsService.AddConnections:input_type -> common.v1.AddConnectionsReq
	5, // 4: things.v1.ThingsService.RemoveConnections:input_type -> common.v1.RemoveConnectionsReq
	1, // 5: things.v1.ThingsService.Authorize:output_type -> things.v1.AuthzRes
	6, // 6: things.v1.ThingsService.RetrieveEntity:output_type -> common.v1.RetrieveEntityRes
	7, // 7: things.v1.ThingsService.RetrieveEntities:output_type -> common.v1.RetrieveEntitiesRes
	8, // 8: things.v1.ThingsService.AddConnections:output_type -> common.v1.AddConnectionsRes
	9, // 9: things.v1.ThingsService.RemoveConnections:output_type -> common.v1.RemoveConnectionsRes
	5, // [5:10] is the sub-list for method output_type
	0, // [0:5] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_things_v1_things_proto_init() }
func file_things_v1_things_proto_init() {
	if File_things_v1_things_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_things_v1_things_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_things_v1_things_proto_goTypes,
		DependencyIndexes: file_things_v1_things_proto_depIdxs,
		MessageInfos:      file_things_v1_things_proto_msgTypes,
	}.Build()
	File_things_v1_things_proto = out.File
	file_things_v1_things_proto_rawDesc = nil
	file_things_v1_things_proto_goTypes = nil
	file_things_v1_things_proto_depIdxs = nil
}
