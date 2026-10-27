# LOCAL_PROVISIONER_HANDOFF — GAME_3D

更新日: 2026-10-27 (Asia/Tokyo)

## 現行統合判定（旧スナップショットより優先）

**HOLD — オフライン実装完了／ライブ作成未確認。** 監督台帳上のGAME_3D active productは`null`で、新規生成ゲートは閉じている。Godot実製品export、正式MSIX、認証済みPartner Center Identity、Factory CAS書戻し、Windows GPU/専用QAはいずれも未実施。Store提出は0件。

- 統合元: `codex/3d-local-identity-provenance-20261027` / `a1727301eddd2966d5f9540ebc287055480c1758`
- ローカル作業ブランチ: `codex/e2e-belt-connection-20261027`
- 自動テスト: **71件 / PASS 69 / FAIL 0 / SKIP 2**（Windows symlink権限制約）
- 共通Schema正規化SHA-256: job `0fbdaf38d25563bf60f756fbf2dd03468517584fb7b05b1bf5f942bf27c1d599` / result `1264f0285283c77aceb2956d687ff3898657578b82ba37ff475a8565f8709310`
- 変更概要: 動的で安全なFactory `codex/*` branch、7項目相関、SHA固定取得、Godot export allowlist、巨大ファイル防止、PFN/Package SID/署名/SHA-256、既存Identity完全照合、GraphQL CAS、PowerShell 7優先。
- Git LFS/外部ストレージを想定し、完成ビルドや巨大生成物をリポジトリへ蓄積しない。

### 起動・返却・次の一手

`python provisioner.py --input job.json --output result.json`。Godot実行には`GODOT_EXE`を安全な環境設定で与える。公式証拠を明示する場合のみ`--official-identity <secure-local-path>`、レビュー後のCAS返却のみ`--apply`。返却先は検証済みFactory作業ブランチ上`products/<slug>/store/approved-identity.json`で、main/releaseは拒否する。

3D active productと正確なrequest_id/source branch/source SHAが正式に指定されるまでHOLD。指定後はDRY_RUN→Godot Windows export/専用QA→公式Identity照合→CAS返却→Factory MSIX→Windows-all-auto 3D隔離キュー→Windows GPU QAの順で再開する。

## 旧判定

**HOLD: オフライン実装、モック検証、DRY_RUNは完了。実製品MSIX生成、Partner Center公式ID取得、Factoryへの実返却は未確認。** テストPASSだけを完成とは扱わない。

## GitHub情報

- Repository: https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D
- 基準: `main` / `67b1cac8c4144f535e87f63f1249846527a5eddd`
- 作業ブランチ: `codex/provisioner-bootstrap-20261026`
- 作業開始時HEAD: `88896a212e7d76296f6678946f9cb637b5779156`
- 資料生成時の実装HEAD: `5f24d054af28a8d76f66894ad815b4a4bc94e658`
- コミット: `88896a2 docs: redirect...`、`5f24d05 feat: implement package identity round-trip provisioner`
- Draft PR: https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D/pull/1
- CI検証済みHEAD: `ab5687189eeeb329063d52b15ff18d086c8f7e17`
- GitHub Actions: SUCCESS — https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D/actions/runs/40382381684
- Provisioner作業ブランチpush: 成功（非force）。
- 差分: Package+Identity CLI、共通Schema、SHA固定取得、Godot Windows export/専用QA、MSIX/署名/PFN/SID解析、型別台帳・排他、公式Identity照合、GitHub CAS返却、CI、テスト。資料更新commit自体のSHAはDraft PRの最新HEADを正とする。

## テスト情報

- 自動テスト: 46件 / PASS 46 / FAIL 0 / SKIP 0
- Python compile: PASS
- DRY_RUN: PASS。build、Partner Center、GitHub writeは0回。
- 実Factory Identity書込: 未実施。Factory側commit SHAなし。
- 実Godot Windows export/MSIX: 未実施。モックMSIX解析のみPASS。
- Partner Center公式ID: 未取得。Store ID推測機能はない。
- 作成・削除したテストリポジトリ: なし。

## 起動と契約

```powershell
python provisioner.py --input job.json --output result.json
python provisioner.py --input job.json --output result.json `
  --official-identity C:\secure\partner-center-evidence.json --apply
```

- 入力: `schemas/job-v1.0.schema.json`
- 出力: `schemas/result-v1.0.schema.json`
- Factory入口: `GAME_3D` / `3d-game-factory`
- 返却先: `shihuiarenjinba-png/3d-game-factory`、`codex/3d-factory-bootstrap-20261026`、`products/<slug>/store/approved-identity.json`
- Windows-all-auto: `type=3d-game`、`expected_head_sha`付きのIdentity返却契約。
- 成功条件: 実MSIXと公式Identityの完全一致、およびGraphQL CASが返す実commit SHA。

## 必要な権限

- GitHub: Factory metadata/read、contents/read、作業ブランチへのcontents/write。main/release権限は不要。
- Partner Center: 対象製品を閲覧できる認証済み担当者。MFA/CAPTCHA回避や未承認の名前予約は禁止。
- 証明書/token/PFXは環境Secret、credential store、証明書ストアで管理し、Gitへ保存しない。

## 重複・復旧

- `.provisioner-state/game_3d/` でrequest fingerprintを記録。同一完了案件は再ビルドせず結果を再掲。
- 同request_idで別入力/SHA、同時起動、既存Identity相違、HEAD不一致は`CONFLICT`。
- HOLD/RETRYABLE_FAILUREは同一入力で再開可能。429/5xx/timeoutは書込済みか再照会してから再試行。
- 既存approved-identity.jsonは一致時のみ`EXISTING_VERIFIED`。自動上書きしない。

## HOLD項目

1. Git credentialによるProvisioner pushは成功したが、`gh auth status`のtokenは失効中。Factory Identity API書込権限は未確認。
2. 承認済み実Factory job、Godot 4実行環境、完成済みexport preset、実MSIXが未提供。
3. 認証済みPartner Centerでの公式Identity確認が未実施。
4. Factory→Provisioner→Windows-all-autoのE2EはChatGPT側の別工程。

CIはWindows/Ubuntuでテストとcompileのみ実行し、権限は`contents: read`。Store提出は行わない。
