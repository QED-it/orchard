window.BENCHMARK_DATA = {
  "lastUpdate": 1756285654837,
  "repoUrl": "https://github.com/QED-it/orchard",
  "entries": {
    "Orchard Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "kris@nutty.land",
            "name": "Kris Nuttycombe",
            "username": "nuttycom"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9d89b504c52dc69064ca431e8311a4cd1c279b44",
          "message": "Merge pull request #470 from QED-it/compatible_with_zsa_halo2\n\nUpdate for compatibility with latest halo2 version (ZSA features)",
          "timestamp": "2025-08-25T08:34:16-06:00",
          "tree_id": "9db33ff4e5d9f4c66c27a6b1e0a87fad19f73a82",
          "url": "https://github.com/QED-it/orchard/commit/9d89b504c52dc69064ca431e8311a4cd1c279b44"
        },
        "date": 1756285653941,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 3025270875,
            "range": "± 324816991",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2987917800,
            "range": "± 8651588",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 4281074028,
            "range": "± 44119333",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 5575057444,
            "range": "± 33671609",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 25088231,
            "range": "± 525833",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 25130892,
            "range": "± 566973",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 28834858,
            "range": "± 718974",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 32623844,
            "range": "± 774054",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1528671,
            "range": "± 31199",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 129332,
            "range": "± 2620",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1525028,
            "range": "± 22450",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1373500853,
            "range": "± 7408828",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 16216578,
            "range": "± 303295",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2198031,
            "range": "± 42747",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 16158186,
            "range": "± 283064",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2136480,
            "range": "± 32405",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 80496934,
            "range": "± 1284702",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 10795815,
            "range": "± 160320",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 80014734,
            "range": "± 1103584",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 10608822,
            "range": "± 129689",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 160302536,
            "range": "± 1897166",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 21593175,
            "range": "± 325418",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 160825512,
            "range": "± 2562175",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 21075686,
            "range": "± 280042",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 474240,
            "range": "± 6796",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 502938,
            "range": "± 7428",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}