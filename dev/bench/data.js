window.BENCHMARK_DATA = {
  "lastUpdate": 1785855920738,
  "repoUrl": "https://github.com/QED-it/orchard",
  "entries": {
    "Orchard Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "ewillbefull@gmail.com",
            "name": "Sean Bowe",
            "username": "ebfull"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "38bd227439117e5bcd031026218299c9ae310095",
          "message": "Merge pull request #541 from ebfull/fingerprint-random-capture\n\nAdd random match-only fingerprint captures (fabricate→replay)",
          "timestamp": "2026-08-03T00:03:48-06:00",
          "tree_id": "df0519585274be89b0ad13063fd50fc173b238f6",
          "url": "https://github.com/QED-it/orchard/commit/38bd227439117e5bcd031026218299c9ae310095"
        },
        "date": 1785855919735,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 2643324278,
            "range": "± 228265191",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 2638173027,
            "range": "± 10299252",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 3817659006,
            "range": "± 23410711",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 4973364678,
            "range": "± 38776998",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 20501094,
            "range": "± 115417",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 20400846,
            "range": "± 206358",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 23618802,
            "range": "± 107839",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 26805820,
            "range": "± 270615",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1367322,
            "range": "± 8684",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 115266,
            "range": "± 5164",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1362456,
            "range": "± 5317",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1227291496,
            "range": "± 3417292",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 13761843,
            "range": "± 17585",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 1242084,
            "range": "± 2988",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 13730417,
            "range": "± 23094",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 1201710,
            "range": "± 3063",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 68712668,
            "range": "± 125809",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 6121889,
            "range": "± 8106",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 68568834,
            "range": "± 172653",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 5921850,
            "range": "± 14849",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 137407918,
            "range": "± 350761",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 12218023,
            "range": "± 13616",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 137131601,
            "range": "± 590152",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 11827909,
            "range": "± 868493",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 419793,
            "range": "± 4459",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 453107,
            "range": "± 738",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}