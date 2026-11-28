package observability

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func MetricsHandler(collectors ...func(io.Writer)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var exposition strings.Builder
		for _, collect := range collectors {
			collect(&exposition)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, exposition.String())
	}
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func Label(value string) string {
	return `"` + labelEscaper.Replace(value) + `"`
}

func BoolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
