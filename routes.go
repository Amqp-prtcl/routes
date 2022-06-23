package routes

import (
	"errors"
	"net/http"
	"regexp"
	"sync"

	"github.com/Amqp-prtcl/jwt"
)

//token will be nil if auth cookie not present
func getToken(r *http.Request, name string) jwt.Token {
	for _, cookie := range r.Cookies() {
		if cookie.Name == "auth" {
			return jwt.Token(cookie.Value)
		}
	}
	return []byte{}
}

type HandlerFunc func(http.ResponseWriter, *http.Request, interface{}, []string)

type Route struct {
	Pattern  *regexp.Regexp
	Method   string
	Handler  HandlerFunc
	AuthType int
}

// AuthType -1 bypasses auth step; meaning that interface field to handle will be nil
func NewRoute(method string, pattern string, AuthType int, handle HandlerFunc) (*Route, error) {
	if AuthType < 0 || AuthType > 3 {
		return nil, errors.New("invalid auth type")
	}
	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Route{
		Pattern:  reg,
		Method:   method,
		Handler:  handle,
		AuthType: AuthType,
	}, nil
}

// like NewRoute bu panic upon error
func MustNewRoute(method string, pattern string, AuthType int, handle HandlerFunc) *Route {
	route, err := NewRoute(method, pattern, AuthType, handle)
	if err != nil {
		panic(err)
	}
	return route
}

type AuthCallback func(*http.Request, int, jwt.Token) (interface{}, bool)

type router struct {
	Routes         []*Route
	OnAuth         AuthCallback
	AuthCookieName string
	mu             sync.RWMutex
}

func NewRouter(auth AuthCallback) *router {
	if auth == nil {
		panic("nil auth callback")
	}
	return &router{
		Routes: []*Route{},
		OnAuth: auth,
		mu:     sync.RWMutex{},
	}
}

func (r *router) ListenAndServe(addr string, auth func()) error {
	return http.ListenAndServe(addr, r)
}

// panics if duplicate pattern and method
func (r *router) AddRoute(route *Route) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rou := range r.Routes {
		if rou.Pattern.String() == route.Pattern.String() && rou.Method == route.Method {
			panic("duplicate routes, pattern: " + route.Pattern.String() + ", method: " + route.Method)
		}
	}
	r.Routes = append(r.Routes, route)
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var hasMatched bool
	r.mu.RLock()
	for _, route := range r.Routes {
		matches := route.Pattern.FindStringSubmatch(req.URL.Path)
		if len(matches) == 0 {
			continue
		}
		if route.Method != "ANY" && req.Method != route.Method {
			hasMatched = true
			continue
		}
		r.mu.RUnlock()

		if r.OnAuth == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		entity, ok := r.OnAuth(req, route.AuthType, getToken(req, r.AuthCookieName))
		if !ok {
			http.Redirect(w, req, "/login", http.StatusSeeOther)
			return
		}

		route.Handler(w, req, entity, matches[1:])
		return
	}
	r.mu.RUnlock()
	if hasMatched {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	http.NotFound(w, req)
	//w.WriteHeader(http.StatusNotFound)
}
