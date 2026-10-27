# 3 Provisioner 横断引継ぎ

APP/GAME/GAME_3Dは同一実装と同一JSON Schemaを使用し、相違は `config.json` の固定Factory、固定作業ブランチ、`WINDOWS` / `GODOT_WINDOWS` adapterだけである。

| 系統 | Factory | 固定ブランチ | build |
|---|---|---|---|
| APP | AI-App-Factory | codex/factory-autoloop-20261026 | WINDOWS |
| GAME | AI-Game-Factory | codex/factory-autoloop-20261026 | WINDOWS |
| GAME_3D | 3d-game-factory | codex/3d-factory-bootstrap-20261026 | GODOT_WINDOWS |

- 共通実装SHA-256: `65c98631d62299bc98a98474a3532e3c7b19d8f6f12eba6b08dd5c2e269a9cbb`
- job schema: `1bddf5a4baa52846ddb3f81702a671d142edf5a0565c3de4e24e47c88f35f1f6`
- result schema: `64a77c4c5afcfedf432fa50c9536a7b7ad5b4a63f64757cbb968a2780c55c23d`
- 共通suiteは各49件、合計147件PASS。APPには既存intake suite 12件（PASS 11 / SKIP 1）も統合され、3リポジトリ総計159件（PASS 158 / FAIL 0 / SKIP 1）。DRY_RUNから同一request_idでの審査済み本実行昇格、衝突時の元台帳保護、Windowsで一時ロックされた台帳ファイルの限定再試行を検証済み。3 CLIのDRY_RUN並列実行PASS。

次工程はGitHub認証復旧、承認済みFactory job供給、Windows/Godot実build、Partner Center公式Identity照合、作業ブランチCAS返却、GitHub Windows Runnerでの正式Identity MSIX再生成。Factory本体、Windows-all-auto本体、5日スケジューラ、Store提出は責任外。
