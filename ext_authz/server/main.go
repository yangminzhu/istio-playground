package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gogo/googleapis/google/rpc"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

var (
	httpPort = flag.String("http", "8000", "HTTP server port")
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
)

// ExtAuthzServer implements the ext_authz gRPC and HTTP check request API.
type ExtAuthzServer struct{}

func check(header string) bool {
	var token string
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimPrefix(header, "Bearer ")
	}
	return token == "allow"
}

// Check implements gRPC check request.
func (s *ExtAuthzServer) Check(ctx context.Context, request *auth.CheckRequest) (*auth.CheckResponse, error) {
	log.Printf("gRPC check attributes: %s\n", request.Attributes)

	if check(request.GetAttributes().GetRequest().GetHttp().GetHeaders()["Authorization"]) {

		return &auth.CheckResponse{
			// This actually sets the cookie for the upstream request.
			// It seems gRPC ext_authz doesn't support setting header for downstream response?
			HttpResponse: &auth.CheckResponse_OkResponse{
				OkResponse: &auth.OkHttpResponse{
					Headers: []*core.HeaderValueOption{
						{
							Header: &core.HeaderValue{
								Key: "Set-Cookie",
								Value: "xt-AuthZ-Custom-Cookie=abcd5678",
							},
						},
					},
				},
			},
			Status: &status.Status{
				Code: int32(rpc.OK),
			},
		}, nil
	}

	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(rpc.PERMISSION_DENIED),
		},
	}, nil
}

// ServeHTTP implements the HTTP check request.
func (s ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	log.Printf("%s check %s%s, headers: %s\n", request.Proto, request.Host, request.URL, request.Header)

	if check(request.Header.Get("Authorization")) {
		// This should set the HTTP header for downstream response.
		response.Header().Set("Set-Cookie", "Ext-AuthZ-Custom-Cookie=abcd1234")
		response.WriteHeader(http.StatusOK)
	} else {
		response.WriteHeader(http.StatusForbidden)
	}
}

func startGRPC(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Printf("Failed to start gRPC server: %v", err)
		return
	}

	s := grpc.NewServer()
	auth.RegisterAuthorizationServer(s, &ExtAuthzServer{})

	log.Printf("Started gRPC server on %s", address)
	if err := s.Serve(listener); err != nil {
		log.Printf("Failed to serve gRPC server: %v", err)
		return
	}
}

func startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	s := &http.Server{
		Addr:    address,
		Handler: ExtAuthzServer{},
	}
	log.Printf("Started HTTP server on %s", address)
	if err := s.ListenAndServe(); err != nil {
		log.Printf("Failed to start HTTP server: %v", err)
	}
}

func main() {
	flag.Parse()
	log.Printf("Init with grpcPort %s and httpPort %s", *grpcPort, *httpPort)

	var wg sync.WaitGroup
	wg.Add(2)
	go startGRPC(fmt.Sprintf(":%s", *grpcPort), &wg)
	go startHTTP(fmt.Sprintf(":%s", *httpPort), &wg)
	wg.Wait()
}
