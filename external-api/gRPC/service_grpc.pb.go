// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: service.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PacketCaptureClient is the client API for PacketCapture service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PacketCaptureClient interface {
	SendPacketMetadataList(ctx context.Context, in *PacketMetadataList, opts ...grpc.CallOption) (*Empty, error)
	SetBPFFilters(ctx context.Context, in *ID, opts ...grpc.CallOption) (PacketCapture_SetBPFFiltersClient, error)
}

type packetCaptureClient struct {
	cc grpc.ClientConnInterface
}

func NewPacketCaptureClient(cc grpc.ClientConnInterface) PacketCaptureClient {
	return &packetCaptureClient{cc}
}

func (c *packetCaptureClient) SendPacketMetadataList(ctx context.Context, in *PacketMetadataList, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/gRPC.PacketCapture/SendPacketMetadataList", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *packetCaptureClient) SetBPFFilters(ctx context.Context, in *ID, opts ...grpc.CallOption) (PacketCapture_SetBPFFiltersClient, error) {
	stream, err := c.cc.NewStream(ctx, &PacketCapture_ServiceDesc.Streams[0], "/gRPC.PacketCapture/SetBPFFilters", opts...)
	if err != nil {
		return nil, err
	}
	x := &packetCaptureSetBPFFiltersClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type PacketCapture_SetBPFFiltersClient interface {
	Recv() (*BPFFilters, error)
	grpc.ClientStream
}

type packetCaptureSetBPFFiltersClient struct {
	grpc.ClientStream
}

func (x *packetCaptureSetBPFFiltersClient) Recv() (*BPFFilters, error) {
	m := new(BPFFilters)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// PacketCaptureServer is the server API for PacketCapture service.
// All implementations must embed UnimplementedPacketCaptureServer
// for forward compatibility
type PacketCaptureServer interface {
	SendPacketMetadataList(context.Context, *PacketMetadataList) (*Empty, error)
	SetBPFFilters(*ID, PacketCapture_SetBPFFiltersServer) error
	mustEmbedUnimplementedPacketCaptureServer()
}

// UnimplementedPacketCaptureServer must be embedded to have forward compatible implementations.
type UnimplementedPacketCaptureServer struct {
}

func (UnimplementedPacketCaptureServer) SendPacketMetadataList(context.Context, *PacketMetadataList) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendPacketMetadataList not implemented")
}
func (UnimplementedPacketCaptureServer) SetBPFFilters(*ID, PacketCapture_SetBPFFiltersServer) error {
	return status.Errorf(codes.Unimplemented, "method SetBPFFilters not implemented")
}
func (UnimplementedPacketCaptureServer) mustEmbedUnimplementedPacketCaptureServer() {}

// UnsafePacketCaptureServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PacketCaptureServer will
// result in compilation errors.
type UnsafePacketCaptureServer interface {
	mustEmbedUnimplementedPacketCaptureServer()
}

func RegisterPacketCaptureServer(s grpc.ServiceRegistrar, srv PacketCaptureServer) {
	s.RegisterService(&PacketCapture_ServiceDesc, srv)
}

func _PacketCapture_SendPacketMetadataList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PacketMetadataList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PacketCaptureServer).SendPacketMetadataList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gRPC.PacketCapture/SendPacketMetadataList",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PacketCaptureServer).SendPacketMetadataList(ctx, req.(*PacketMetadataList))
	}
	return interceptor(ctx, in, info, handler)
}

func _PacketCapture_SetBPFFilters_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ID)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PacketCaptureServer).SetBPFFilters(m, &packetCaptureSetBPFFiltersServer{stream})
}

type PacketCapture_SetBPFFiltersServer interface {
	Send(*BPFFilters) error
	grpc.ServerStream
}

type packetCaptureSetBPFFiltersServer struct {
	grpc.ServerStream
}

func (x *packetCaptureSetBPFFiltersServer) Send(m *BPFFilters) error {
	return x.ServerStream.SendMsg(m)
}

// PacketCapture_ServiceDesc is the grpc.ServiceDesc for PacketCapture service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PacketCapture_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "gRPC.PacketCapture",
	HandlerType: (*PacketCaptureServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendPacketMetadataList",
			Handler:    _PacketCapture_SendPacketMetadataList_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SetBPFFilters",
			Handler:       _PacketCapture_SetBPFFilters_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "service.proto",
}
