# Build stage
FROM golang:1.23 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM redhat/ubi9-minimal
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8443
CMD ["./app/main"]
