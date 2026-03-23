window.BENCHMARK_DATA = {
  "lastUpdate": 1774253502133,
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
          "distinct": false,
          "id": "64599b81ef4fee59c41a5b98619e27a8be38f953",
          "message": "Merge pull request #477 from zcash/pczt_extract_reference\n\nMake pczt::Bundle::extract take `self` by reference.",
          "timestamp": "2026-03-03T09:50:03-08:00",
          "tree_id": "32086be78565bb131d6647582abacf35963dccfe",
          "url": "https://github.com/QED-it/orchard/commit/64599b81ef4fee59c41a5b98619e27a8be38f953"
        },
        "date": 1774253500899,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2696507719,
            "range": "± 107822859",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2689239899,
            "range": "± 2796500",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 3842946245,
            "range": "± 15951013",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 5042389487,
            "range": "± 27116479",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 21166480,
            "range": "± 190149",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 21257976,
            "range": "± 191061",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 24665705,
            "range": "± 187072",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 27973597,
            "range": "± 221348",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1483885,
            "range": "± 10438",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 125776,
            "range": "± 393",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1480079,
            "range": "± 11863",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1345567106,
            "range": "± 4190285",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 15662174,
            "range": "± 39805",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2133014,
            "range": "± 26778",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 15640475,
            "range": "± 116179",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2098338,
            "range": "± 5735",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 78249727,
            "range": "± 195659",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 10607107,
            "range": "± 32496",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 78120678,
            "range": "± 104278",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 10435430,
            "range": "± 51805",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 156495167,
            "range": "± 282596",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 21201411,
            "range": "± 55714",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 156171580,
            "range": "± 600248",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 20850749,
            "range": "± 25555",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 461751,
            "range": "± 2716",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 488446,
            "range": "± 2357",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}