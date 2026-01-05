package utils

import "net/http"

func RespondJSONError(w http.ResponseWriter, code int, msg string) error {
	return RespondJSON(w, code, map[string]string{"error": msg})
}
