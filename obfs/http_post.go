package obfs

import (
	"math/rand"
	"time"
)

func init() {
	register("http_post", newHttpPost)
}

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object
	rand.Seed(time.Now().UnixNano())
	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      false,
	}
	return t
}
