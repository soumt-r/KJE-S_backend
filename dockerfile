FROM golang:alpine as builder
ENV CGO_ENABLED=1
WORKDIR /app
COPY go.mod go.sum ./
RUN apk add --no-cache --update git build-base
RUN go mod download

COPY . .
RUN go build -o kjes_backend .

FROM alpine:latest as runner
ENV TZ=Asia/Seoul
RUN apk --no-cache add ca-certificates tzdata libc6-compat libgcc libstdc++
WORKDIR /app

COPY --from=builder /app/kjes_backend /app/kjes_backend
EXPOSE 5000

ENTRYPOINT [ "./kjes_backend" ]