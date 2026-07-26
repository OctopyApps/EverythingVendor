package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Logger пишет записи аудита в audit_log. Логируются как разрешённые,
// так и отклонённые действия — это данные для расследования инцидентов.
type Logger struct {
	pool *pgxpool.Pool
}

func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

type Entry struct {
	TenantID  uuid.UUID
	ActorID   *uuid.UUID
	Action    string
	Module    string
	Entity    string
	RecordID  *uuid.UUID
	Result    string // "allowed" | "denied"
	Metadata  map[string]any
	IPAddress string
}

// Record пишет запись аудита. Ошибка записи аудита не должна ронять
// основной запрос пользователя, поэтому вызывающий код обычно только
// логирует err через slog, не возвращая его клиенту — но и не должна
// проглатываться молча, иначе потеряем видимость проблем с аудитом.
func (l *Logger) Record(ctx context.Context, e Entry) error {
	var metadataJSON []byte
	if e.Metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(e.Metadata)
		if err != nil {
			slog.Error("audit: failed to marshal metadata", "error", err)
			metadataJSON = nil
		}
	}

	var ipParam any
	if e.IPAddress != "" {
		ipParam = e.IPAddress
	}

	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, actor_id, action, module, entity, record_id, result, metadata, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, e.TenantID, e.ActorID, e.Action, nullIfEmpty(e.Module), nullIfEmpty(e.Entity), e.RecordID, e.Result, metadataJSON, ipParam)

	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
