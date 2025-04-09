window.BENCHMARK_DATA = {
  "lastUpdate": 1744217293180,
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
          "id": "fcb14defd75c0dd79512289c17a1ac46b5001d3a",
          "message": "Merge pull request #461 from daira/ci-fixes-from-460\n\nCI and dependency fixes for `no_std`",
          "timestamp": "2025-03-19T09:26:31-06:00",
          "tree_id": "b5ae77ea88aedae2fbbc4fb02592db0047c3adca",
          "url": "https://github.com/QED-it/orchard/commit/fcb14defd75c0dd79512289c17a1ac46b5001d3a"
        },
        "date": 1744217292487,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2860203044,
            "range": "± 310984379",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2844562364,
            "range": "± 32157009",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 4065289468,
            "range": "± 30125946",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 5339978437,
            "range": "± 24686551",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 24353940,
            "range": "± 275656",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 24378664,
            "range": "± 648038",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 27571003,
            "range": "± 421136",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 31244745,
            "range": "± 229822",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1473880,
            "range": "± 19478",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 125517,
            "range": "± 352",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1470207,
            "range": "± 4641",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1329945414,
            "range": "± 1524426",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 15558725,
            "range": "± 17890",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2131583,
            "range": "± 3927",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 15538301,
            "range": "± 26271",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2096792,
            "range": "± 3672",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 77739855,
            "range": "± 161696",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 10606800,
            "range": "± 30491",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 77602781,
            "range": "± 111294",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 10431520,
            "range": "± 16399",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 155382774,
            "range": "± 168457",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 21187792,
            "range": "± 34023",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 155284959,
            "range": "± 623670",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 20847679,
            "range": "± 36022",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 463121,
            "range": "± 1032",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 488366,
            "range": "± 1412",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}