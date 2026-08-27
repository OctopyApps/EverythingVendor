// Package modules реализует Реестр модулей: разбор и валидацию манифеста,
// который каждый модуль публикует для регистрации в ядре платформы.
//
// На этом шаге пакет отвечает только за схему манифеста и её структурную
// валидацию (docs/architecture.md §5). Регистрация модуля в Entity Engine,
// RBAC, API-gateway и шине событий — отдельный будущий шаг (Registry.Register),
// который будет построен поверх типов этого файла.
package modules

// FieldType — тип поля сущности модуля в Entity Engine.
type FieldType string

const (
	FieldTypeString FieldType = "string"
	FieldTypeText   FieldType = "text"
	FieldTypeInt    FieldType = "int"
	FieldTypeFloat  FieldType = "float"
	FieldTypeBool   FieldType = "bool"
	FieldTypeUUID   FieldType = "uuid"
	FieldTypeTime   FieldType = "timestamp"
	FieldTypeJSON   FieldType = "json"
)

// FieldDef описывает одно поле сущности.
type FieldDef struct {
	Name     string    `yaml:"name"`
	Type     FieldType `yaml:"type"`
	Required bool      `yaml:"required"`
	// Ref — опционально: имя сущности (в т.ч. другого модуля), на которую
	// ссылается поле (FK), например "contact" для deal.contact_id.
	// Существование указанной сущности на этом шаге не проверяется —
	// это задача Registry.Register, у которого есть доступ к уже
	// зарегистрированным модулям.
	Ref string `yaml:"ref,omitempty"`
}

// EntityAction — допустимые действия над сущностью, под которые ядро
// сгенерирует permissions по умолчанию (module.entity:action).
type EntityAction string

const (
	ActionRead   EntityAction = "read"
	ActionWrite  EntityAction = "write"
	ActionDelete EntityAction = "delete"
	ActionExport EntityAction = "export"
)

// EntityDef — одна сущность, которую модуль регистрирует в Entity Engine.
type EntityDef struct {
	Name        string         `yaml:"name"`
	Fields      []FieldDef     `yaml:"fields"`
	Permissions []EntityAction `yaml:"permissions"`
}

// EventsDef — события, которые модуль публикует/на которые подписывается.
// На шаге "Реестр модулей" это только валидируется (уникальность в пределах
// списка, формат "module.event"); фактическая шина NATS подключается позже
// (см. roadmap.md, "Обвязка publish/subscribe для NATS JetStream").
type EventsDef struct {
	Publishes  []string `yaml:"publishes,omitempty"`
	Subscribes []string `yaml:"subscribes,omitempty"`
}

// UIDef — пункты меню, которые модуль добавляет во фронтенд-оболочку.
type UIDef struct {
	MenuItems []string `yaml:"menu_items,omitempty"`
}

// APIDef — точка монтирования REST API модуля в API-gateway ядра.
type APIDef struct {
	// BasePath — префикс маршрутов, генерируемых Entity Engine ядра
	// для сущностей этого модуля. Обязателен всегда.
	BasePath string `yaml:"base_path"`

	// ServiceURL — опционально: адрес уже развёрнутого и работающего
	// сервиса модуля, если модулю нужна кастомная логика сверх generic
	// CRUD (например, почта или llm-gateway). Если пусто — модуль
	// полностью декларативный и обслуживается ядром без обращения к
	// какому-либо внешнему процессу. См. docs/architecture.md §5.1.
	ServiceURL string `yaml:"service_url,omitempty"`
}

// DeploymentDef — опциональные метаданные для будущего оркестратора
// (магазин модулей, Фаза 6). На этом шаге это только данные без какой-либо
// логики разворачивания — заводим их сейчас, чтобы не менять формат
// манифеста повторно. См. docs/architecture.md §5.1.
type DeploymentDef struct {
	// Image — опционально: docker-образ модуля (registry/name:tag).
	Image string `yaml:"image,omitempty"`
	// EnvSchema — опционально: имена env-переменных/секретов, которые
	// потребуются сервису модуля при разворачивании.
	EnvSchema []string `yaml:"env_schema,omitempty"`
	// HealthPath — опционально: путь для health-check после разворачивания.
	HealthPath string `yaml:"health_path,omitempty"`
}

// Manifest — полное описание модуля, публикуемое им при регистрации в ядре.
// Соответствует контракту из docs/architecture.md §5.
type Manifest struct {
	Module   string        `yaml:"module"`
	Version  string        `yaml:"version"`
	Entities []EntityDef   `yaml:"entities"`
	Events   EventsDef     `yaml:"events"`
	UI       UIDef         `yaml:"ui"`
	API      APIDef        `yaml:"api"`
	// Deployment — опционален; задаётся только у сервисных модулей,
	// планирующих участвовать в будущем магазине модулей (Фаза 6).
	Deployment *DeploymentDef `yaml:"deployment,omitempty"`
}
