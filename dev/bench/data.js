window.BENCHMARK_DATA = {
  "lastUpdate": 1789628608340,
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
          "id": "f2be3a479837df6583110fd44e124d155ec592ee",
          "message": "Merge pull request #551 from zcash/dw/zizmor-and-pin-actions\n\nSetup Zizmor",
          "timestamp": "2026-09-09T10:02:47-06:00",
          "tree_id": "f62032bb6ddbeaa03e5101b6e324ca930e28c607",
          "url": "https://github.com/QED-it/orchard/commit/f2be3a479837df6583110fd44e124d155ec592ee"
        },
        "date": 1789628606597,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2047677940,
            "range": "± 12857420",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2046829615,
            "range": "± 4338760",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 2944848198,
            "range": "± 18623037",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 3874452672,
            "range": "± 34015210",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 16001157,
            "range": "± 141212",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 15960130,
            "range": "± 102252",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 18527153,
            "range": "± 144862",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 20817279,
            "range": "± 186746",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1065002,
            "range": "± 4798",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 89732,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1061820,
            "range": "± 8030",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 939906257,
            "range": "± 4090687",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 10717187,
            "range": "± 23800",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 964651,
            "range": "± 13061",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 10692634,
            "range": "± 60523",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 932842,
            "range": "± 1130",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 53512363,
            "range": "± 75602",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 4754228,
            "range": "± 63578",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 53377464,
            "range": "± 132839",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 4596433,
            "range": "± 75073",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 106996447,
            "range": "± 363217",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 9475939,
            "range": "± 14384",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 106695306,
            "range": "± 84181",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 9159018,
            "range": "± 12056",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 323710,
            "range": "± 2545",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 347119,
            "range": "± 7116",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}