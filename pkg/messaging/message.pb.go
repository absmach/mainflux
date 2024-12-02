// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v5.29.0
// source: pkg/messaging/message.proto

package messaging

import (
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

// Message represents a message emitted by the Magistrala adapters layer.
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Channel   string `protobuf:"bytes,1,opt,name=channel,proto3" json:"channel,omitempty"`
	Subtopic  string `protobuf:"bytes,2,opt,name=subtopic,proto3" json:"subtopic,omitempty"`
	Publisher string `protobuf:"bytes,3,opt,name=publisher,proto3" json:"publisher,omitempty"`
	Protocol  string `protobuf:"bytes,4,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Payload   []byte `protobuf:"bytes,5,opt,name=payload,proto3" json:"payload,omitempty"`
	Created   int64  `protobuf:"varint,6,opt,name=created,proto3" json:"created,omitempty"` // Unix timestamp in nanoseconds
}

func (x *Message) Reset() {
	*x = Message{}
	mi := &file_pkg_messaging_message_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_messaging_message_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_pkg_messaging_message_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetChannel() string {
	if x != nil {
		return x.Channel
	}
	return ""
}

func (x *Message) GetSubtopic() string {
	if x != nil {
		return x.Subtopic
	}
	return ""
}

func (x *Message) GetPublisher() string {
	if x != nil {
		return x.Publisher
	}
	return ""
}

func (x *Message) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *Message) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Message) GetCreated() int64 {
	if x != nil {
		return x.Created
	}
	return 0
}

var File_pkg_messaging_message_proto protoreflect.FileDescriptor

var file_pkg_messaging_message_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x70, 0x6b, 0x67, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x69, 0x6e, 0x67, 0x2f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x69, 0x6e, 0x67, 0x22, 0xad, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x12, 0x1a,
	0x0a, 0x08, 0x73, 0x75, 0x62, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x73, 0x75, 0x62, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x18,
	0x0a, 0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x42, 0x0d, 0x5a, 0x0b, 0x2e, 0x2f, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_messaging_message_proto_rawDescOnce sync.Once
	file_pkg_messaging_message_proto_rawDescData = file_pkg_messaging_message_proto_rawDesc
)

func file_pkg_messaging_message_proto_rawDescGZIP() []byte {
	file_pkg_messaging_message_proto_rawDescOnce.Do(func() {
		file_pkg_messaging_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_messaging_message_proto_rawDescData)
	})
	return file_pkg_messaging_message_proto_rawDescData
}

var file_pkg_messaging_message_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pkg_messaging_message_proto_goTypes = []any{
	(*Message)(nil), // 0: messaging.Message
}
var file_pkg_messaging_message_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pkg_messaging_message_proto_init() }
func file_pkg_messaging_message_proto_init() {
	if File_pkg_messaging_message_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_messaging_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_messaging_message_proto_goTypes,
		DependencyIndexes: file_pkg_messaging_message_proto_depIdxs,
		MessageInfos:      file_pkg_messaging_message_proto_msgTypes,
	}.Build()
	File_pkg_messaging_message_proto = out.File
	file_pkg_messaging_message_proto_rawDesc = nil
	file_pkg_messaging_message_proto_goTypes = nil
	file_pkg_messaging_message_proto_depIdxs = nil
}
