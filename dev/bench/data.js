window.BENCHMARK_DATA = {
  "lastUpdate": 1649240759777,
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
          "id": "420d600f0e8276559c50710faf7730ebab35dbec",
          "message": "Merge pull request #305 from zcash/fvk-scope\n\nAdd explicit scoping for viewing keys and addresses",
          "timestamp": "2022-03-30T08:37:20-06:00",
          "tree_id": "4958705fc0ecef315e6352013db8b2c344659784",
          "url": "https://github.com/QED-it/orchard/commit/420d600f0e8276559c50710faf7730ebab35dbec"
        },
        "date": 1649240758929,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 4901274604,
            "range": "± 38109458",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 4920130828,
            "range": "± 18814925",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 7030036121,
            "range": "± 136947196",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 9146656099,
            "range": "± 28086614",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 38027755,
            "range": "± 767464",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 37998779,
            "range": "± 467616",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 43010485,
            "range": "± 909348",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 47127332,
            "range": "± 824048",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1233846,
            "range": "± 11920",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 157414,
            "range": "± 2012",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1216337,
            "range": "± 17098",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 161006118,
            "range": "± 1734590",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 24148806,
            "range": "± 244964",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2796045,
            "range": "± 23543",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 23877260,
            "range": "± 236696",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2760733,
            "range": "± 17637",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 120494710,
            "range": "± 817653",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 13990307,
            "range": "± 42524",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 120534155,
            "range": "± 811642",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 13768304,
            "range": "± 81715",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 240838771,
            "range": "± 1891750",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 27856114,
            "range": "± 209075",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 241367778,
            "range": "± 1094617",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 27383599,
            "range": "± 237646",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 590480,
            "range": "± 11702",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 647662,
            "range": "± 7480",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}