package modules

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ParseManifest разбирает YAML-манифест модуля и сразу валидирует его через
// ValidateManifest. Возвращает ошибку разбора YAML или первую найденную
// ошибку валидации — вызывающий код (Registry.Register) не должен пытаться
// зарегистрировать невалидный манифест.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest yaml: %w", err)
	}
	if err := ValidateManifest(&m); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}
	return &m, nil
}
