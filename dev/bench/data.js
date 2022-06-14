window.BENCHMARK_DATA = {
  "lastUpdate": 1655221191052,
  "repoUrl": "https://github.com/QED-it/orchard",
  "entries": {
    "Orchard Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "jack@electriccoin.co",
            "name": "str4d",
            "username": "str4d"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "de37f1cdbcff53e5ab26a485d058bf8c41bd5626",
          "message": "Merge pull request #328 from zcash/release-0.1.0\n\nRelease 0.1.0",
          "timestamp": "2022-05-11T00:05:04+01:00",
          "tree_id": "324bc3f9556eaaa818ac438fd0b9cc283e17a7c0",
          "url": "https://github.com/QED-it/orchard/commit/de37f1cdbcff53e5ab26a485d058bf8c41bd5626"
        },
        "date": 1652349256852,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 3791379411,
            "range": "± 318936737",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 3659027536,
            "range": "± 182239041",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 5070445541,
            "range": "± 194442966",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 6685826361,
            "range": "± 315021340",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 29812152,
            "range": "± 1642742",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 32590494,
            "range": "± 1785202",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 33103732,
            "range": "± 2052203",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 39337309,
            "range": "± 6299035",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 928400,
            "range": "± 592",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 117091,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 922682,
            "range": "± 2075",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 117756832,
            "range": "± 49652",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 18207826,
            "range": "± 13698",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2342308,
            "range": "± 1500",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 18162423,
            "range": "± 8110",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2035895,
            "range": "± 1707",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 90974173,
            "range": "± 124629",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 11657954,
            "range": "± 4792",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 90761017,
            "range": "± 39533",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 10129136,
            "range": "± 4431",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 182017236,
            "range": "± 392443",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 20568937,
            "range": "± 16414",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 181462383,
            "range": "± 116769",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 20239946,
            "range": "± 14886",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 494256,
            "range": "± 2520",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 546900,
            "range": "± 514",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "jack@electriccoin.co",
            "name": "str4d",
            "username": "str4d"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "36d263fb19cf4b88200617c4bbe7a91b66bf4869",
          "message": "Merge pull request #321 from zcash/protocol-rule-links\n\nAdd protocol rule links for the Orchard circuit constraints",
          "timestamp": "2022-05-27T17:03:05+01:00",
          "tree_id": "fecb70418689fa5f4048eb6b81ddc8953043125d",
          "url": "https://github.com/QED-it/orchard/commit/36d263fb19cf4b88200617c4bbe7a91b66bf4869"
        },
        "date": 1655221190213,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 3893795479,
            "range": "± 16222846",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 3868488117,
            "range": "± 17119947",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 5515052701,
            "range": "± 21991671",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 7158033544,
            "range": "± 18752264",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 33111199,
            "range": "± 263249",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 33119849,
            "range": "± 427185",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 37281411,
            "range": "± 1234678",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 40717020,
            "range": "± 288109",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1045939,
            "range": "± 646",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 116947,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1043074,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 120038781,
            "range": "± 54442",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 18147966,
            "range": "± 8149",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2063422,
            "range": "± 1037",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 20375238,
            "range": "± 11555",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2304159,
            "range": "± 1664",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 102822613,
            "range": "± 52337",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 11634078,
            "range": "± 3782",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 102501214,
            "range": "± 43298",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 11363207,
            "range": "± 7850",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 205613977,
            "range": "± 111766",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 23263572,
            "range": "± 7411",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 205002480,
            "range": "± 53905",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 22903984,
            "range": "± 7374",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 494256,
            "range": "± 538",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 546303,
            "range": "± 327",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}