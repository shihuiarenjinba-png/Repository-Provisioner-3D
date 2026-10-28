# Repository-Provisioner-3D

`3d-game-factory` で確定したGAME_3Dを、SHA固定で取得し、Godotのheadless Windows exportと専用ソースQAを行い、MSIXのIdentityを認証済みPartner Centerの公式値と照合してFactoryへ返す中間工程です。巨大ファイルはGitに追加せず、新規リポジトリ作成、Store ID推測、Store提出、main/releaseへの書込みは行いません。

## 実行

Python 3.12以降、Git/GitHub CLI、Godot 4（`GODOT_EXE` またはPATH）が必要です。DRY_RUNは外部読取・export・GitHub書込みを行いません。

```powershell
python provisioner.py --input examples/job.dry-run.json --output test-results/dry-run.json
```

実処理では `project.godot` と `export_presets.cfg`、Factoryブランチの正確なHEAD SHA、認証済みPartner Center証跡、正式Identityを含むMSIX候補が必要です。GitHub返却は `--apply` のときだけ実施します。

```powershell
python provisioner.py --input job.json --output result.json `
  --official-identity C:\secure\partner-center-evidence.json --apply
```

返却先リポジトリは `shihuiarenjinba-png/3d-game-factory` に固定し、ブランチは入力 `source_branch` と同じ安全な `codex/*` 作業ブランチを使用します。`main`、`release`、不正なブランチ名は拒否します。返却パスは `products/<slug>/store/approved-identity.json` です。入力・出力契約は `schemas/`、運用とHOLD項目は `docs/LOCAL_PROVISIONER_HANDOFF.md` を参照してください。


> Current 3D Factory route: `codex/3d-real-msix-build-path-20261027`. The
> Provisioner returns `verified_source_sha` in `approved-identity.json`
> together with the authenticated Partner Center evidence fields. This is
> required by the Factory's fail-closed MSIX builder; Identity remains HOLD
> without genuine operator-supplied evidence and an exact source HEAD.


## 3D Factory export provenance gate (Identity 前)

GAME_3D の `candidate.exe` を検査した場合、Identity 照会前に、独立した GitHub Actions 実行情報と Factory export Artifact ZIP の実バイトを検証します。これは実製品が Factory から生成された後の契約であり、現状の非製品 Godot/MakeAppx fixture を販売製品として承認するものではありません。

```powershell
gh auth status --hostname github.com
python provisioner.py --input job.json --output result.json `
  --factory-run-id <FACTORY_RUN_ID> `
  --factory-artifact-id <FACTORY_ARTIFACT_ID> `
  --official-identity C:\secure\partner-center-evidence.json
```

`--factory-run-id` と `--factory-artifact-id` は、受け入れ済み Factory 製品の実際の export run と `godot-3d-factory-export-evidence` Artifact を指定します。GitHub CLI `gh api` は認証済みの GitHub REST API から run と Artifact のメタデータを別々に取得し、Artifact ZIP をダウンロードします。検証器は ZIP の GitHub SHA-256 digest、run 成功状態、`request_id`・`slug`・不変の `source_sha`、別管理の `factory_build_head`、EXE/PCK サイズと SHA-256 を照合します。欠落・不一致・期限切れ・ダウンロード失敗時は **Identity 照会前に HOLD** です。

Identity が未取得でも `factory_export_evidence` に `PRE_IDENTITY_BYTES_CORRELATED` 証拠を保持できます。ただしこの証拠は `POST_IDENTITY_READY`、実製品MSIX、GPU、Windows install、GUI、Store E2E の合格ではありません。新3D製品生成と120時間ゲートは引き続き HOLD です。
