// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: teleport/resourceusage/v1/access_requests.proto

package resourceusagev1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// AccessRequestsUsage defines the usage limits for access requests.
// Usage is limited on the basis of access requests used per calendar month.
type AccessRequestsUsage struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// MonthlyLimit is the amount of requests that are allowed per month
	MonthlyLimit int32 `protobuf:"varint,1,opt,name=monthly_limit,json=monthlyLimit,proto3" json:"monthly_limit,omitempty"`
	// MonthlyUsed is the amount of requests that have been used this month
	MonthlyUsed   int32 `protobuf:"varint,2,opt,name=monthly_used,json=monthlyUsed,proto3" json:"monthly_used,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AccessRequestsUsage) Reset() {
	*x = AccessRequestsUsage{}
	mi := &file_teleport_resourceusage_v1_access_requests_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AccessRequestsUsage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessRequestsUsage) ProtoMessage() {}

func (x *AccessRequestsUsage) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_resourceusage_v1_access_requests_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessRequestsUsage.ProtoReflect.Descriptor instead.
func (*AccessRequestsUsage) Descriptor() ([]byte, []int) {
	return file_teleport_resourceusage_v1_access_requests_proto_rawDescGZIP(), []int{0}
}

func (x *AccessRequestsUsage) GetMonthlyLimit() int32 {
	if x != nil {
		return x.MonthlyLimit
	}
	return 0
}

func (x *AccessRequestsUsage) GetMonthlyUsed() int32 {
	if x != nil {
		return x.MonthlyUsed
	}
	return 0
}

var File_teleport_resourceusage_v1_access_requests_proto protoreflect.FileDescriptor

const file_teleport_resourceusage_v1_access_requests_proto_rawDesc = "" +
	"\n" +
	"/teleport/resourceusage/v1/access_requests.proto\x12\x19teleport.resourceusage.v1\"]\n" +
	"\x13AccessRequestsUsage\x12#\n" +
	"\rmonthly_limit\x18\x01 \x01(\x05R\fmonthlyLimit\x12!\n" +
	"\fmonthly_used\x18\x02 \x01(\x05R\vmonthlyUsedB^Z\\github.com/gravitational/teleport/api/gen/proto/go/teleport/resourceusage/v1;resourceusagev1b\x06proto3"

var (
	file_teleport_resourceusage_v1_access_requests_proto_rawDescOnce sync.Once
	file_teleport_resourceusage_v1_access_requests_proto_rawDescData []byte
)

func file_teleport_resourceusage_v1_access_requests_proto_rawDescGZIP() []byte {
	file_teleport_resourceusage_v1_access_requests_proto_rawDescOnce.Do(func() {
		file_teleport_resourceusage_v1_access_requests_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_teleport_resourceusage_v1_access_requests_proto_rawDesc), len(file_teleport_resourceusage_v1_access_requests_proto_rawDesc)))
	})
	return file_teleport_resourceusage_v1_access_requests_proto_rawDescData
}

var file_teleport_resourceusage_v1_access_requests_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_resourceusage_v1_access_requests_proto_goTypes = []any{
	(*AccessRequestsUsage)(nil), // 0: teleport.resourceusage.v1.AccessRequestsUsage
}
var file_teleport_resourceusage_v1_access_requests_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_resourceusage_v1_access_requests_proto_init() }
func file_teleport_resourceusage_v1_access_requests_proto_init() {
	if File_teleport_resourceusage_v1_access_requests_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_teleport_resourceusage_v1_access_requests_proto_rawDesc), len(file_teleport_resourceusage_v1_access_requests_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_resourceusage_v1_access_requests_proto_goTypes,
		DependencyIndexes: file_teleport_resourceusage_v1_access_requests_proto_depIdxs,
		MessageInfos:      file_teleport_resourceusage_v1_access_requests_proto_msgTypes,
	}.Build()
	File_teleport_resourceusage_v1_access_requests_proto = out.File
	file_teleport_resourceusage_v1_access_requests_proto_goTypes = nil
	file_teleport_resourceusage_v1_access_requests_proto_depIdxs = nil
}
