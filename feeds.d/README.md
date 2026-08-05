# Feed descriptors

A feed descriptor tells CTHULHU how to read a log format it does not
understand natively. Rules in `alerts.jrl` then target the feed by name:

```text
web_path_traversal(high)
    | "Path traversal attempt"
    ~ on: nginx          # <- the feed defined by feeds.d/nginx.json
    : http_path contains ["../"]
```

auditd and journald are built in and need no descriptor. This directory is
only for additional sources — nginx, Kubernetes audit, an appliance's syslog.
Files ending in `.example` are inert until you rename them.

---

Drop a `.json` file here to add a data source without writing any Python.
CTHULHU registers it at startup; rules then target it with `~ on: <name>`.

Copy an `.example` file, remove the suffix, and adjust:

    cp nginx.json.example nginx.json
    cth feeds        # confirm it registered
    cth check        # confirm rules referencing it validate

Fields captured by named regex groups (or JSON keys) become rule fields
automatically, so `(?P<http_status>\d{3})` is usable as `http_status` in JRL.

Keys:

| key               | meaning                                            |
|-------------------|----------------------------------------------------|
| `name`            | feed name used by `~ on:`                          |
| `paths` / `path`  | file(s) to tail; globs allowed                     |
| `format`          | `regex` or `json`                                  |
| `pattern`         | regex with named groups (regex format only)        |
| `field_map`       | rename source keys to schema field names           |
| `types`           | coerce fields to `int` / `float` / `bool`          |
| `static`          | constant fields added to every event               |
| `timestamp_field` | which captured field holds the event time          |
| `category`        | event category, e.g. `web`                         |
| `enabled`         | set false to register but not collect              |
