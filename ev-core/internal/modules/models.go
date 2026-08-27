package modules

import "errors"

// Sentinel-ошибки структурной валидации манифеста. ValidateManifest
// возвращает первую найденную ошибку, обёрнутую через fmt.Errorf("%w", ...)
// с указанием места (сущность/поле/индекс) — сравнивать через errors.Is.
var (
	ErrModuleNameEmpty   = errors.New("module: name is required")
	ErrModuleNameInvalid = errors.New("module: name must match ^[a-z][a-z0-9_]*$")
	ErrVersionEmpty      = errors.New("module: version is required")
	ErrVersionInvalid    = errors.New("module: version must be semver, e.g. 1.0.0")

	ErrNoEntities          = errors.New("module: must declare at least one entity")
	ErrEntityNameEmpty     = errors.New("entity: name is required")
	ErrEntityNameInvalid   = errors.New("entity: name must match ^[a-z][a-z0-9_]*$")
	ErrEntityNameDuplicate = errors.New("entity: duplicate entity name in manifest")
	ErrEntityNoFields      = errors.New("entity: must declare at least one field")
	ErrEntityActionInvalid = errors.New("entity: invalid permission action")

	ErrFieldNameEmpty     = errors.New("field: name is required")
	ErrFieldNameInvalid   = errors.New("field: name must match ^[a-z][a-z0-9_]*$")
	ErrFieldNameDuplicate = errors.New("field: duplicate field name in entity")
	ErrFieldTypeInvalid   = errors.New("field: invalid type")

	ErrBasePathEmpty    = errors.New("api.base_path: is required")
	ErrBasePathInvalid  = errors.New("api.base_path: must start with /api/ and contain only lowercase letters, digits, hyphens and slashes")
	ErrBasePathReserved = errors.New("api.base_path: collides with a reserved core path")
	ErrServiceURLInvalid = errors.New("api.service_url: must be a valid http(s) URL")

	ErrEventNameInvalid    = errors.New("events: event name must match ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$")
	ErrDuplicatePublishes  = errors.New("events.publishes: duplicate event name")
	ErrDuplicateSubscribes = errors.New("events.subscribes: duplicate event name")

	ErrDeploymentImageInvalid = errors.New("deployment.image: must not be empty when deployment block is present")
)
