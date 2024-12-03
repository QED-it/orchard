window.BENCHMARK_DATA = {
  "lastUpdate": 1733220047957,
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
          "id": "23a167e3972632586dc628ddbdd69d156dfd607b",
          "message": "Merge pull request #438 from zcash/release/orchard-0.10.0\n\nRelease orchard version 0.10.0",
          "timestamp": "2024-10-02T11:33:46-06:00",
          "tree_id": "9d992e16f125248281ea0f6cd8b72b3995b97b30",
          "url": "https://github.com/QED-it/orchard/commit/23a167e3972632586dc628ddbdd69d156dfd607b"
        },
        "date": 1733220046668,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2928417337,
            "range": "± 266415064",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2892417925,
            "range": "± 20112970",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 4155210999,
            "range": "± 31971209",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 5429953458,
            "range": "± 21434441",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 25069174,
            "range": "± 715137",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 25412816,
            "range": "± 950279",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 28192816,
            "range": "± 900078",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 31780715,
            "range": "± 552512",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1527437,
            "range": "± 9617",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 128000,
            "range": "± 601",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1524411,
            "range": "± 3081",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1363560969,
            "range": "± 3455718",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 16119477,
            "range": "± 13705",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2169247,
            "range": "± 2922",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 16101066,
            "range": "± 162986",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2138846,
            "range": "± 8118",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 80525893,
            "range": "± 178077",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 10792261,
            "range": "± 205081",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 80450648,
            "range": "± 452736",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 10635381,
            "range": "± 46192",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 161080001,
            "range": "± 1120674",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 21568041,
            "range": "± 635598",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 160855540,
            "range": "± 1181140",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 21260676,
            "range": "± 66712",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 468066,
            "range": "± 1239",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 502666,
            "range": "± 2921",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}