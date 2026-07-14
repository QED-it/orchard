window.BENCHMARK_DATA = {
  "lastUpdate": 1784020902200,
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
          "id": "d9bfa9fa6e86a9c83213bce932f1cf84c55432c5",
          "message": "Merge pull request #516 from zcash/feat/ironwood\n\nAdd support for the Ironwood shielded pool.",
          "timestamp": "2026-07-11T12:02:52+02:00",
          "tree_id": "93ba7b7a424d05e45e108b1e83af9d0e8275324b",
          "url": "https://github.com/QED-it/orchard/commit/d9bfa9fa6e86a9c83213bce932f1cf84c55432c5"
        },
        "date": 1784020901154,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2725525953,
            "range": "± 31034730",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2724704216,
            "range": "± 3404843",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 3931897824,
            "range": "± 13608891",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 5087573856,
            "range": "± 54359406",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 22073264,
            "range": "± 287849",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 22207579,
            "range": "± 268054",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 25543698,
            "range": "± 210804",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 29062658,
            "range": "± 272661",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1574358,
            "range": "± 4879",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 134316,
            "range": "± 1496",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1573095,
            "range": "± 7185",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1422023337,
            "range": "± 1424914",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 16650962,
            "range": "± 297002",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2289222,
            "range": "± 3426",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 16617490,
            "range": "± 38462",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2248782,
            "range": "± 3661",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 83177082,
            "range": "± 210174",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 11381866,
            "range": "± 163718",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 83033891,
            "range": "± 98553",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 11188642,
            "range": "± 16607",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 166322131,
            "range": "± 296614",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 22743275,
            "range": "± 39917",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 166013772,
            "range": "± 174789",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 22346783,
            "range": "± 56586",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 489286,
            "range": "± 6590",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 521807,
            "range": "± 784",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}