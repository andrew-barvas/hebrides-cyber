Real gospider v1.1.6 output, captured 2026-10-06 by running

    gospider -s http://127.0.0.1:8098/ -c 5 -d 2 --json -t 5 --sitemap --robots --timeout 5

against a local page linking `/about` and loading `/static/app.js`, whose
script names `/api/v1/users`, `/api/internal/admin/export`, an S3 object
(`acme-uploads.s3.amazonaws.com`) and a third-party library
(`cdn.example.org`). Even with `--json`, gospider prints a plain-text status
line (`[url] - [code-200] - …`) among the JSON ones, kept as captured.
