# Minimal SDS Server and Envoy 

You can run the SDS server and envoy using the project top-level Makefile, e.g.:

```
$ make example
```

The Makefile builds the SDS server and then runs `build/example.sh` which runs both Envoy and the SDS server.  The SDS server serves a configuration defined in `internal/example/resource.go`.

## Python realization of automate task for obtaining certificates via Let's encrypt (ACME v2 staging environment)

You need follow this requirements for success validation of your domain name and obtain certificate https://letsencrypt.org/docs/challenge-types/#http-01-challenge

```
$ pip3 install -r requirements.txt
$ python3 acme_cert.py
```

After successful operation you can find a new certificate and key in `./envoy/certs`

## Files

* [resource.go](resource.go) generates a `Snapshot` structure which describes the configuration that the SDS server serves to Envoy.
* [bootstrap-xds.yaml](bootstrap-xds.yaml) Envoy configuration
* [acme_cert.py](acme_cert.py) Python realization of automate task for obtaining certificates via Let's encrypt (ACME v2 staging environment)
