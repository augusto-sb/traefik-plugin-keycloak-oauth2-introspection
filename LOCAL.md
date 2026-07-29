```bash
podman container run --rm -p 8080:8080 \
  -v ./example-static-local.yml:/static.yml:ro \
  -v ./example-dynamic-local.yml:/dynamic.yml:ro \
  -v .:/plugins-local/src/github.com/augusto-sb/traefik-plugin-keycloak-oauth2-introspection:ro \
  docker.io/library/traefik:3.7.9 \
  traefik --configFile=/static.yml;
```