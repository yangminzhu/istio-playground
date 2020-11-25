// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

const (
	checkHeader  = "x-ext-authz"
	allowedValue = "allow"
	resultHeader = "x-ext-authz-result"
)

var (
	httpPort = flag.String("http", "8000", "HTTP server port")
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
)

// ExtAuthzServer implements the ext_authz gRPC and HTTP check request API.
type ExtAuthzServer struct {
	// For test only
	httpPort chan int
	grpcPort chan int
}

// Check implements gRPC check request.
func (s *ExtAuthzServer) Check(ctx context.Context, request *auth.CheckRequest) (*auth.CheckResponse, error) {
	if allowedValue == request.GetAttributes().GetRequest().GetHttp().GetHeaders()[checkHeader] {
		log.Printf("[gRPC][allowed]: %s%s with attributes %v\n",
			request.GetAttributes().GetRequest().GetHttp().GetHost(),
			request.GetAttributes().GetRequest().GetHttp().GetPath(),
			request.GetAttributes())
		return &auth.CheckResponse{
			// This actually sets the cookie for the upstream request.
			// It seems gRPC ext_authz doesn't support setting header for downstream response?
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key:   resultHeader,
								Value: "allowed",
							},
						},
					},
				},
			},
			Status: &status.Status{Code: int32(rpc.OK)},
		}, nil
	}

	log.Printf("[gRPC][ denied]: %s%s with attributes %v\n",
		request.GetAttributes().GetRequest().GetHttp().GetHost(),
		request.GetAttributes().GetRequest().GetHttp().GetPath(),
		request.GetAttributes())
	return &auth.CheckResponse{
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   resultHeader,
							Value: "denied",
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(rpc.PERMISSION_DENIED)},
	}, nil
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if allowedValue == request.Header.Get(checkHeader) {
		log.Printf("[HTTP][allowed]: %s %s%s with headers: %s\n", request.Method, request.Host, request.URL, request.Header)
		response.Header().Set(resultHeader, "allowed")
		response.WriteHeader(http.StatusOK)
	} else {
		log.Printf("[HTTP][ denied]: %s %s%s with headers: %s\n", request.Method, request.Host, request.URL, request.Header)
		response.Header().Set(resultHeader, "denied")
		response.WriteHeader(http.StatusForbidden)
	}
}

func (s *ExtAuthzServer) startGRPC(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
		return
	}
	// Store the port for test only.
	s.grpcPort <- listener.Addr().(*net.TCPAddr).Port

	server := grpc.NewServer()
	auth.RegisterAuthorizationServer(server, &ExtAuthzServer{})

	log.Printf("Starting gRPC server at %s", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
		return
	}
}

func (s *ExtAuthzServer) startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}
	// Store the port for test only.
	s.httpPort <- listener.Addr().(*net.TCPAddr).Port

	log.Printf("Starting HTTP server at %s", listener.Addr())
	if err := http.Serve(listener, s); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func (s *ExtAuthzServer) run(httpAddr, grpcAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startGRPC(httpAddr, &wg)
	go s.startHTTP(grpcAddr, &wg)
	wg.Wait()
}

func main() {
	flag.Parse()
	s := &ExtAuthzServer{httpPort: make(chan int, 1), grpcPort: make(chan int, 1)}
	s.run(fmt.Sprintf(":%s", *httpPort), fmt.Sprintf(":%s", *grpcPort))
}
