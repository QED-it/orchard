window.BENCHMARK_DATA = {
  "lastUpdate": 1670338990315,
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
          "distinct": false,
          "id": "3faab98e9e82618a0f2d887054e9e28b0f7947dd",
          "message": "Merge pull request #342 from zcash/release-0.2.0\n\nRelease 0.2.0",
          "timestamp": "2022-06-24T17:23:22+01:00",
          "tree_id": "c1dda5f72c5100a527057bd293cc8c818e944193",
          "url": "https://github.com/QED-it/orchard/commit/3faab98e9e82618a0f2d887054e9e28b0f7947dd"
        },
        "date": 1658139082409,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 4717205726,
            "range": "± 87488353",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 4670377457,
            "range": "± 30921748",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 6701700452,
            "range": "± 112080862",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 8624170793,
            "range": "± 145860585",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 35908753,
            "range": "± 1107141",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 36081828,
            "range": "± 1018508",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 41328894,
            "range": "± 2553075",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 44805310,
            "range": "± 7640654",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 1268441,
            "range": "± 6724",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 158761,
            "range": "± 1561",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1263680,
            "range": "± 7289",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 162550187,
            "range": "± 727335",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 24945213,
            "range": "± 127222",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 2815065,
            "range": "± 12452",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 24884795,
            "range": "± 98285",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2762484,
            "range": "± 5810",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 123868900,
            "range": "± 258938",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 13960162,
            "range": "± 32918",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 124196759,
            "range": "± 323221",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 13752223,
            "range": "± 50714",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 247503862,
            "range": "± 399189",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 27906850,
            "range": "± 83312",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 246926055,
            "range": "± 703251",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 27442845,
            "range": "± 116109",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 622597,
            "range": "± 31455",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 656575,
            "range": "± 2472",
            "unit": "ns/iter"
          }
        ]
      },
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
          "id": "d05b6cee9df7c4019509e2f54899b5979fb641b5",
          "message": "Merge pull request #362 from zcash/batch-scanner-improvements\n\nBatch scanner improvements",
          "timestamp": "2022-10-20T09:30:49-06:00",
          "tree_id": "45c0b7bd0fb04c9de8adc3078a3e29e8956c28fe",
          "url": "https://github.com/QED-it/orchard/commit/d05b6cee9df7c4019509e2f54899b5979fb641b5"
        },
        "date": 1670338988827,
        "tool": "cargo",
        "benches": [
          {
            "name": "proving/bundle/1",
            "value": 5018513631,
            "range": "± 127159770",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/2",
            "value": 4971123710,
            "range": "± 44705015",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/3",
            "value": 7106439931,
            "range": "± 83734661",
            "unit": "ns/iter"
          },
          {
            "name": "proving/bundle/4",
            "value": 9251354819,
            "range": "± 96157963",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/1",
            "value": 43561148,
            "range": "± 4257800",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/2",
            "value": 43089342,
            "range": "± 4438738",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/3",
            "value": 47230810,
            "range": "± 6952680",
            "unit": "ns/iter"
          },
          {
            "name": "verifying/bundle/4",
            "value": 58025219,
            "range": "± 9285391",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/valid",
            "value": 2133521,
            "range": "± 71648",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/invalid",
            "value": 177201,
            "range": "± 8156",
            "unit": "ns/iter"
          },
          {
            "name": "note-decryption/compact-valid",
            "value": 1962953,
            "range": "± 87747",
            "unit": "ns/iter"
          },
          {
            "name": "compact-note-decryption/invalid",
            "value": 1740710181,
            "range": "± 29635404",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/10",
            "value": 22656087,
            "range": "± 900148",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/10",
            "value": 3010750,
            "range": "± 156805",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/10",
            "value": 20381970,
            "range": "± 938507",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/10",
            "value": 2757533,
            "range": "± 145725",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/50",
            "value": 111885370,
            "range": "± 3071607",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/50",
            "value": 13973139,
            "range": "± 551041",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/50",
            "value": 102802037,
            "range": "± 3449554",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/50",
            "value": 13684402,
            "range": "± 742921",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/valid/100",
            "value": 225146448,
            "range": "± 5846755",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/invalid/100",
            "value": 27581496,
            "range": "± 1105471",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-valid/100",
            "value": 206898540,
            "range": "± 6734778",
            "unit": "ns/iter"
          },
          {
            "name": "batch-note-decryption/compact-invalid/100",
            "value": 27082483,
            "range": "± 981690",
            "unit": "ns/iter"
          },
          {
            "name": "derive_fvk",
            "value": 599984,
            "range": "± 26944",
            "unit": "ns/iter"
          },
          {
            "name": "default_address",
            "value": 676782,
            "range": "± 38048",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}