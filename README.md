# how to

## example

configure your traefik with plugin and middleware and test with curl
as in example-*.yml files
you need:
- endpoint https://example.com/auth/realms/<realm-name>/protocol/openid-connect/token/introspect
- client
- client secret

## start container

```bash
docker container run --rm -p 8080:8080 \
  -v ./example-static.yml:/static.yml:ro \
  -v ./example-dynamic.yml:/dynamic.yml:ro \
  docker.io/library/traefik:v3.6.15 \
  traefik --configFile=/static.yml;
```

## get token

```bash
curl -d 'client_id=public-client' -d 'username=complete' -d 'password=complete' -d 'grant_type=password' 'https://example.com/auth/realms/<realm-name>/protocol/openid-connect/token'
```

## test plugin (with previous access_token)

```bash
curl http://localhost:8080 -H 'Host: example.com' -H 'Authorization: Bearer ...' -v
```



# info

https://doc.traefik.io/traefik/v3.6/reference/install-configuration/configuration-options/

# prod volume to avoid redownload

/plugins-storage