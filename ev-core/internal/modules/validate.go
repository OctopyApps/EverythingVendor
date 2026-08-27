package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	moduleNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	entityNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	fieldNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	semverRe     = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	basePathRe   = regexp.MustCompile(`^/api/[a-z0-9\-/]+$`)
	// eventNameRe требует минимум два сегмента через точку, например
	// "crm.deal_won" или "email.classified" — без требования отдельного
	// сегмента под entity, см. обсуждение в docs/architecture.md §5.1.
	eventNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// reservedBasePaths — префиксы, занятые самим ядром; модуль не может их
// перекрыть своим api.base_path.
var reservedBasePaths = []string{"/api/core", "/api/auth"}

var validFieldTypes = map[FieldType]bool{
	FieldTypeString: true,
	FieldTypeText:   true,
	FieldTypeInt:    true,
	FieldTypeFloat:  true,
	FieldTypeBool:   true,
	FieldTypeUUID:   true,
	FieldTypeTime:   true,
	FieldTypeJSON:   true,
}

var validEntityActions = map[EntityAction]bool{
	ActionRead:   true,
	ActionWrite:  true,
	ActionDelete: true,
	ActionExport: true,
}

// ValidateManifest проверяет манифест модуля целиком и возвращает первую
// найденную ошибку. Валидация чисто структурная/синтаксическая — не
// обращается к БД или к уже зарегистрированным модулям. Проверки, которые
// требуют знания о других модулях (например, что api.base_path не занят
// другим уже зарегистрированным модулем, или что Ref в FieldDef указывает
// на реально существующую сущность), выполняются отдельно в Registry.Register.
func ValidateManifest(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest is nil")
	}
	if err := validateHeader(m); err != nil {
		return err
	}
	if err := validateEntities(m.Entities); err != nil {
		return err
	}
	if err := validateAPI(m.API); err != nil {
		return err
	}
	if err := validateEvents(m.Events); err != nil {
		return err
	}
	if err := validateDeployment(m.Deployment); err != nil {
		return err
	}
	return nil
}

func validateHeader(m *Manifest) error {
	if m.Module == "" {
		return ErrModuleNameEmpty
	}
	if !moduleNameRe.MatchString(m.Module) {
		return fmt.Errorf("module %q: %w", m.Module, ErrModuleNameInvalid)
	}
	if m.Version == "" {
		return ErrVersionEmpty
	}
	if !semverRe.MatchString(m.Version) {
		return fmt.Errorf("version %q: %w", m.Version, ErrVersionInvalid)
	}
	return nil
}

func validateEntities(entities []EntityDef) error {
	if len(entities) == 0 {
		return ErrNoEntities
	}

	seenEntities := make(map[string]bool, len(entities))
	for _, e := range entities {
		if e.Name == "" {
			return ErrEntityNameEmpty
		}
		if !entityNameRe.MatchString(e.Name) {
			return fmt.Errorf("entity %q: %w", e.Name, ErrEntityNameInvalid)
		}
		if seenEntities[e.Name] {
			return fmt.Errorf("entity %q: %w", e.Name, ErrEntityNameDuplicate)
		}
		seenEntities[e.Name] = true

		if err := validateFields(e.Name, e.Fields); err != nil {
			return err
		}
		if err := validateEntityActions(e.Name, e.Permissions); err != nil {
			return err
		}
	}
	return nil
}

func validateFields(entityName string, fields []FieldDef) error {
	if len(fields) == 0 {
		return fmt.Errorf("entity %q: %w", entityName, ErrEntityNoFields)
	}

	seenFields := make(map[string]bool, len(fields))
	for _, f := range fields {
		if f.Name == "" {
			return fmt.Errorf("entity %q: %w", entityName, ErrFieldNameEmpty)
		}
		if !fieldNameRe.MatchString(f.Name) {
			return fmt.Errorf("entity %q, field %q: %w", entityName, f.Name, ErrFieldNameInvalid)
		}
		if seenFields[f.Name] {
			return fmt.Errorf("entity %q, field %q: %w", entityName, f.Name, ErrFieldNameDuplicate)
		}
		seenFields[f.Name] = true

		// Ref опционален и на этом шаге не проверяется на существование —
		// только то, что тип поля валиден.
		if !validFieldTypes[f.Type] {
			return fmt.Errorf("entity %q, field %q: type %q: %w", entityName, f.Name, f.Type, ErrFieldTypeInvalid)
		}
	}
	return nil
}

func validateEntityActions(entityName string, actions []EntityAction) error {
	for _, a := range actions {
		if !validEntityActions[a] {
			return fmt.Errorf("entity %q: action %q: %w", entityName, a, ErrEntityActionInvalid)
		}
	}
	return nil
}

func validateAPI(api APIDef) error {
	if api.BasePath == "" {
		return ErrBasePathEmpty
	}
	if !basePathRe.MatchString(api.BasePath) {
		return fmt.Errorf("api.base_path %q: %w", api.BasePath, ErrBasePathInvalid)
	}
	for _, reserved := range reservedBasePaths {
		if api.BasePath == reserved || strings.HasPrefix(api.BasePath, reserved+"/") {
			return fmt.Errorf("api.base_path %q: %w (%s)", api.BasePath, ErrBasePathReserved, reserved)
		}
	}

	if api.ServiceURL != "" {
		u, err := url.Parse(api.ServiceURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("api.service_url %q: %w", api.ServiceURL, ErrServiceURLInvalid)
		}
	}
	return nil
}

func validateEvents(events EventsDef) error {
	if err := validateEventNames(events.Publishes, ErrDuplicatePublishes); err != nil {
		return err
	}
	if err := validateEventNames(events.Subscribes, ErrDuplicateSubscribes); err != nil {
		return err
	}
	return nil
}

func validateEventNames(names []string, duplicateErr error) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !eventNameRe.MatchString(name) {
			return fmt.Errorf("event %q: %w", name, ErrEventNameInvalid)
		}
		if seen[name] {
			return fmt.Errorf("event %q: %w", name, duplicateErr)
		}
		seen[name] = true
	}
	return nil
}

func validateDeployment(d *DeploymentDef) error {
	if d == nil {
		return nil
	}
	// Deployment — опциональный блок целиком, но если модуль его указал,
	// image обязателен: без него блок бессмыслен для будущего оркестратора.
	if strings.TrimSpace(d.Image) == "" {
		return ErrDeploymentImageInvalid
	}
	return nil
}
