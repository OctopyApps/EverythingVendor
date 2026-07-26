.PHONY: gen-keys docker-up docker-down migrate-up migrate-down run tidy

# Генерация пары RSA-ключей для подписи JWT (RS256).
# Приватный ключ (jwt_private.pem) НИКОГДА не коммитить в git.
gen-keys:
	mkdir -p keys
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/jwt_private.pem
	openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem
	chmod 600 keys/jwt_private.pem

docker-up:
	docker compose up -d

docker-down:
	docker compose down

# DATABASE_URL берём из .env вручную/через export перед вызовом, либо подставь напрямую.
migrate-up:
	migrate -path migrations -database "$$DATABASE_URL" up

migrate-down:
	migrate -path migrations -database "$$DATABASE_URL" down 1

tidy:
	go mod tidy

run:
	go run ./cmd/core
