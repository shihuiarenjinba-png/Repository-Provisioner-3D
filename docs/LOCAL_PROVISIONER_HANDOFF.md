# LOCAL_PROVISIONER_HANDOFF — GAME_3D

更新日: 2026-10-27 (Asia/Tokyo)

## 判定

**HOLD: オフライン実装、モック検証、DRY_RUNは完了。実製品MSIX生成、Partner Center公式ID取得、Factoryへの実返却は未確認。** テストPASSだけを完成とは扱わない。

## GitHub情報

- Repository: https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D
- 基準: `main` / `67b1cac8c4144f535e87f63f1249846527a5eddd`
- 作業ブランチ: `codex/provisioner-bootstrap-20261026`
- 作業開始時HEAD: `88896a212e7d76296f6678946f9cb637b5779156`
- 資料生成時の実装HEAD: `5f24d054af28a8d76f66894ad815b4a4bc94e658`
- コミット: `88896a2 docs: redirect...`、`5f24d05 feat: implement package identity round-trip provisioner`
- Draft PR: https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D/pull/1
- 実装・テスト検証HEAD: `00b16f0a6040885f37ff00ec79c821e12f26fad1`
- GitHub CI: https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D/actions/runs/40423366537 （Windows / Ubuntu とも成功）
- GitHub Actions: SUCCESS — https://github.com/shihuiarenjinba-png/Repository-Provisioner-3D/actions/runs/40382381684
- Provisioner作業ブランチpush: 成功（非force）。
- 差分: Package+Identity CLI、共通Schema、SHA固定取得、Godot Windows export/専用QA、MSIX/署名/PFN/SID解析、型別台帳・排他、公式Identity照合、GitHub CAS返却、CI、テスト。資料更新commit自体のSHAはDraft PRの最新HEADを正とする。

## テスト情報

- 自動テスト: 49件 / PASS 49 / FAIL 0 / SKIP 0
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
