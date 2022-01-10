package istio.authz

import input.attributes.request.http as http_request
import input.parsed_path

default allow = false

allow {
	parsed_path[0] == "health"
	http_request.method == "GET"
}

allow {
	roles_for_user[r]
	required_roles[r]
}

allow {
	http_request.path == "/"
}

roles_for_user[r] {
	r := user_roles[user_name][_]
}

required_roles[r] {
	perm := role_perms[r][_]
	perm.method = http_request.method
	perm.path = http_request.path
}

user_name = parsed {
	[_, encoded] := split(http_request.headers.authorization, " ")
	[parsed, _] := split(base64url.decode(encoded), ":")
}

user_roles = {
	"dahn": ["guest"],
	"bob": ["admin"],
}

role_perms = {
	"guest": [{"method": "GET", "path": "/index"}],
	"admin": [
		{"method": "GET", "path": "/productpage"},
		{"method": "GET", "path": "/api/v1/products"},
	],
}

jwks_request(url) = http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 3600, # Cache response for an hour
})

allow {
	jwks = jwks_request("https://idp-demo.dev.trustid.ch/auth/realms/servicemesh-internship/protocol/openid-connect/certs").raw_body
	print("before")
	print(input.attributes.request.http.headers.authorization)
	verified = io.jwt.verify_rs256(input.attributes.request.http.headers.authorization, jwks)
	print("after")
	print(verified)
	verified == true
}
