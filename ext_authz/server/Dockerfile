FROM golang:1.13 as build

WORKDIR /ext_authz_server
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build main.go

FROM gcr.io/distroless/base

COPY --from=build /ext_authz_server/main /
ENTRYPOINT ["/main"]
