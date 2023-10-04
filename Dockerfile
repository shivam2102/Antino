FROM golang:1.16.6-alpine3.14 AS builder
WORKDIR /server
ENV GO111MODULE=on
COPY go.mod /server/
COPY go.sum /server/

RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -o /go/bin/assignment

FROM scratch
COPY --from=builder /server/database/migration ./database/migration
COPY --from=builder /go/bin/assignment /go/bin/assignment
EXPOSE 8080
ENTRYPOINT ["/go/bin/assignment"]