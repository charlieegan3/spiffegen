// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: spiffeconnector.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetCredentialsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Credentials []*Credential `protobuf:"bytes,1,rep,name=Credentials,proto3" json:"Credentials,omitempty"`
}

func (x *GetCredentialsResponse) Reset() {
	*x = GetCredentialsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_spiffeconnector_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCredentialsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCredentialsResponse) ProtoMessage() {}

func (x *GetCredentialsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_spiffeconnector_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCredentialsResponse.ProtoReflect.Descriptor instead.
func (*GetCredentialsResponse) Descriptor() ([]byte, []int) {
	return file_spiffeconnector_proto_rawDescGZIP(), []int{0}
}

func (x *GetCredentialsResponse) GetCredentials() []*Credential {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type Credential struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Files    []*File                `protobuf:"bytes,1,rep,name=Files,proto3" json:"Files,omitempty"`
	EnvVars  map[string]string      `protobuf:"bytes,2,rep,name=EnvVars,proto3" json:"EnvVars,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Username *string                `protobuf:"bytes,3,opt,name=Username,proto3,oneof" json:"Username,omitempty"`
	Password *string                `protobuf:"bytes,4,opt,name=Password,proto3,oneof" json:"Password,omitempty"`
	Token    *string                `protobuf:"bytes,5,opt,name=Token,proto3,oneof" json:"Token,omitempty"`
	NotAfter *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=NotAfter,proto3,oneof" json:"NotAfter,omitempty"`
}

func (x *Credential) Reset() {
	*x = Credential{}
	if protoimpl.UnsafeEnabled {
		mi := &file_spiffeconnector_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Credential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credential) ProtoMessage() {}

func (x *Credential) ProtoReflect() protoreflect.Message {
	mi := &file_spiffeconnector_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credential.ProtoReflect.Descriptor instead.
func (*Credential) Descriptor() ([]byte, []int) {
	return file_spiffeconnector_proto_rawDescGZIP(), []int{1}
}

func (x *Credential) GetFiles() []*File {
	if x != nil {
		return x.Files
	}
	return nil
}

func (x *Credential) GetEnvVars() map[string]string {
	if x != nil {
		return x.EnvVars
	}
	return nil
}

func (x *Credential) GetUsername() string {
	if x != nil && x.Username != nil {
		return *x.Username
	}
	return ""
}

func (x *Credential) GetPassword() string {
	if x != nil && x.Password != nil {
		return *x.Password
	}
	return ""
}

func (x *Credential) GetToken() string {
	if x != nil && x.Token != nil {
		return *x.Token
	}
	return ""
}

func (x *Credential) GetNotAfter() *timestamppb.Timestamp {
	if x != nil {
		return x.NotAfter
	}
	return nil
}

type File struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Path     string `protobuf:"bytes,1,opt,name=Path,proto3" json:"Path,omitempty"`
	Mode     uint32 `protobuf:"varint,2,opt,name=Mode,proto3" json:"Mode,omitempty"`
	Contents []byte `protobuf:"bytes,3,opt,name=Contents,proto3" json:"Contents,omitempty"`
}

func (x *File) Reset() {
	*x = File{}
	if protoimpl.UnsafeEnabled {
		mi := &file_spiffeconnector_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *File) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*File) ProtoMessage() {}

func (x *File) ProtoReflect() protoreflect.Message {
	mi := &file_spiffeconnector_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use File.ProtoReflect.Descriptor instead.
func (*File) Descriptor() ([]byte, []int) {
	return file_spiffeconnector_proto_rawDescGZIP(), []int{2}
}

func (x *File) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *File) GetMode() uint32 {
	if x != nil {
		return x.Mode
	}
	return 0
}

func (x *File) GetContents() []byte {
	if x != nil {
		return x.Contents
	}
	return nil
}

var File_spiffeconnector_proto protoreflect.FileDescriptor

var file_spiffeconnector_proto_rawDesc = []byte{
	0x0a, 0x15, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x47, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x2d, 0x0a, 0x0b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
	0x6c, 0x52, 0x0b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22, 0xe4,
	0x02, 0x0a, 0x0a, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x12, 0x1b, 0x0a,
	0x05, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x46,
	0x69, 0x6c, 0x65, 0x52, 0x05, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x12, 0x32, 0x0a, 0x07, 0x45, 0x6e,
	0x76, 0x56, 0x61, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x43, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x2e, 0x45, 0x6e, 0x76, 0x56, 0x61, 0x72, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x45, 0x6e, 0x76, 0x56, 0x61, 0x72, 0x73, 0x12, 0x1f,
	0x0a, 0x08, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x08, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x12,
	0x1f, 0x0a, 0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x01, 0x52, 0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x88, 0x01, 0x01,
	0x12, 0x19, 0x0a, 0x05, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x02, 0x52, 0x05, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x3b, 0x0a, 0x08, 0x4e,
	0x6f, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x03, 0x52, 0x08, 0x4e, 0x6f, 0x74,
	0x41, 0x66, 0x74, 0x65, 0x72, 0x88, 0x01, 0x01, 0x1a, 0x3a, 0x0a, 0x0c, 0x45, 0x6e, 0x76, 0x56,
	0x61, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x42, 0x08,
	0x0a, 0x06, 0x5f, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x4e, 0x6f, 0x74,
	0x41, 0x66, 0x74, 0x65, 0x72, 0x22, 0x4a, 0x0a, 0x04, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x50, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x50, 0x61, 0x74,
	0x68, 0x12, 0x12, 0x0a, 0x04, 0x4d, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x04, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x73, 0x32, 0x54, 0x0a, 0x0f, 0x53, 0x70, 0x69, 0x66, 0x66, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x12, 0x41, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x17,
	0x2e, 0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x46, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6a, 0x65, 0x74, 0x73, 0x74, 0x61, 0x63, 0x6b, 0x2f, 0x73,
	0x70, 0x69, 0x66, 0x66, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2f,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_spiffeconnector_proto_rawDescOnce sync.Once
	file_spiffeconnector_proto_rawDescData = file_spiffeconnector_proto_rawDesc
)

func file_spiffeconnector_proto_rawDescGZIP() []byte {
	file_spiffeconnector_proto_rawDescOnce.Do(func() {
		file_spiffeconnector_proto_rawDescData = protoimpl.X.CompressGZIP(file_spiffeconnector_proto_rawDescData)
	})
	return file_spiffeconnector_proto_rawDescData
}

var file_spiffeconnector_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_spiffeconnector_proto_goTypes = []interface{}{
	(*GetCredentialsResponse)(nil), // 0: GetCredentialsResponse
	(*Credential)(nil),             // 1: Credential
	(*File)(nil),                   // 2: File
	nil,                            // 3: Credential.EnvVarsEntry
	(*timestamppb.Timestamp)(nil),  // 4: google.protobuf.Timestamp
	(*emptypb.Empty)(nil),          // 5: google.protobuf.Empty
}
var file_spiffeconnector_proto_depIdxs = []int32{
	1, // 0: GetCredentialsResponse.Credentials:type_name -> Credential
	2, // 1: Credential.Files:type_name -> File
	3, // 2: Credential.EnvVars:type_name -> Credential.EnvVarsEntry
	4, // 3: Credential.NotAfter:type_name -> google.protobuf.Timestamp
	5, // 4: SpiffeConnector.GetCredentials:input_type -> google.protobuf.Empty
	0, // 5: SpiffeConnector.GetCredentials:output_type -> GetCredentialsResponse
	5, // [5:6] is the sub-list for method output_type
	4, // [4:5] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_spiffeconnector_proto_init() }
func file_spiffeconnector_proto_init() {
	if File_spiffeconnector_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_spiffeconnector_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCredentialsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_spiffeconnector_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Credential); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_spiffeconnector_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*File); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_spiffeconnector_proto_msgTypes[1].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_spiffeconnector_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_spiffeconnector_proto_goTypes,
		DependencyIndexes: file_spiffeconnector_proto_depIdxs,
		MessageInfos:      file_spiffeconnector_proto_msgTypes,
	}.Build()
	File_spiffeconnector_proto = out.File
	file_spiffeconnector_proto_rawDesc = nil
	file_spiffeconnector_proto_goTypes = nil
	file_spiffeconnector_proto_depIdxs = nil
}
