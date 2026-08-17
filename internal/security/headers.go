package security

import "net/http"

func Apply(header http.Header, values map[string]string) {
	for key, value := range values {
		if key != "" && value != "" {
			header.Set(key, value)
		}
	}
}
