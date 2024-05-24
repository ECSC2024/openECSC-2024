FROM golang:1.21-bookworm AS build

RUN apt update && apt install -y libxml2-dev

WORKDIR /usr/local/src/backend

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN GOOS=linux go build -v -o /usr/local/bin/backend

FROM debian:bookworm

RUN apt update && apt install -y libxml2
COPY --from=build /usr/local/bin/backend /usr/local/bin/backend

ENTRYPOINT ["/usr/local/bin/backend"]
CMD []
