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

返却先は `shihuiarenjinba-png/3d-game-factory` の `codex/3d-provisioner-job-contract-20261027`、`products/<slug>/store/approved-identity.json` に固定されています。入力・出力契約は `schemas/`、運用とHOLD項目は `docs/LOCAL_PROVISIONER_HANDOFF.md` を参照してください。
