package config

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

const CONFIG_ENV_PREFIX = "XSPA"
const PROFILE_ENV_PREFIX = "XSPA_PROFILE"

func FillFromEnvs(target interface{}, prefix string) {
	v := reflect.ValueOf(target)

	if v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}

	v = v.Elem()

	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.Anonymous {
			continue
		}

		envName := prefix + "_" + toSnakeUpper(field.Name)
		if val := os.Getenv(envName); val != "" {
			f := v.Field(i)
			if f.CanSet() {
				switch f.Kind() {
				case reflect.String:
					f.SetString(val)
				case reflect.Uint32:
					if uv, err := strconv.ParseUint(val, 10, 32); err == nil {
						f.SetUint(uv)
					}
				}
			}
		}
	}
}

func ExpandSecrets(target interface{}) {
	v := reflect.ValueOf(target)

	if v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}
	v = v.Elem()

	if v.Kind() != reflect.Struct {
		return
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if strings.HasSuffix(field.Name, "Secret") {
			filePathField := v.Field(i)
			path := filePathField.String()

			if path == "" {
				continue
			}

			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			secretData := strings.TrimSpace(string(content))

			targetFieldName := strings.TrimSuffix(field.Name, "Secret")
			targetField := v.FieldByName(targetFieldName)
			if targetField.IsValid() && targetField.CanSet() {
				targetField.SetString(secretData)
			}
		}
	}
}

func toSnakeUpper(s string) string {
	var res []rune
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			prev := rune(s[i-1])
			if unicode.IsLower(prev) {
				res = append(res, '_')
			} else if i+1 < len(s) && unicode.IsLower(rune(s[i+1])) {
				res = append(res, '_')
			}
		}
		res = append(res, unicode.ToUpper(r))
	}
	return string(res)
}
