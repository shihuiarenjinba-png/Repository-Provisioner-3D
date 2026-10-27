# ローカル担当への優先変更指示（2026-10-26）

**現在の新しい最優先業務**：これまでの「新製品ごとにGitHubリポジトリを大量新設する」設計から、「Factoryで確定した製品名を受け取り、ローカルWindowsでパッケージ/公式Identityを検査・取得し、正しいFactory work branchへ返す」中間製造工程に変更する。

このProvisionerの専任種別：`GAME_3D`。Factory：`shihuiarenjinba-png/3d-game-factory`。GitHub結果返却先：`shihuiarenjinba-png/3d-game-factory` の `codex/3d-factory-bootstrap-20261026` ブランチ、`products/<slug>/store/approved-identity.json`。内部Windows-all-auto Identityルータの種別は `3d-game`。

## 必須実装
1. Factoryが作成した **製品名・slug・request_id・source factory/repo/work branch・正確なcommit SHA** を受け取る。製品名のみでrepoやStore IDを推測してはいけない。入力は厳密なJSON Schemaをバージョン管理し、3製品で一致検査。種別違いはHOLD。
2. GitHubから正確なソースSHAを取得してWindowsでパッケージを生成・検査。APP/GAMEは既存のWindows buildの事実を確認。GAME_3Dの場合はGodot Windows export/実行試験とMSIX化の未整備を明示して段階ごとHOLDする。ビルド物・重い3D素材をGitの通常コミットに追加しない。
3. MSIX内部のName、Publisher、Version、PFN、SID、SHA256は解析できるが、**新しいMicrosoft Store IDはMSIX内部から取得できない**。Partner Centerに登録済みの正式Store ID/Identity Name/Publisherのみを認証済み環境から取得・照合。名前予約・新規登録が必要な場合は権限・ユーザー許可の確認を行い、無許可の登録やMFA回避をしない。
4. 公式Partner Center URL、確認担当、時刻、製品との一致を記録。Windows-all-autoの `all_auto.identity_route`／`identity_commit` 既存契約へ厳密なアダプタを作成。対象Factory repo・branch・slugを固定のallowlistと当該source SHAで検査し、HEAD不一致や既存approved-identity.jsonがあれば上書きせずHOLD。成功時は実際のGitHub commit SHAを返す。
5. 正式Identity返却後、GitHub Windows Runner側がStore用MSIXを再生成する。Factory→Windows-all-auto→ローカルQAの本体接続はChatGPT側。新規GitHubリポジトリ生成は今回の標準動作から外す。
6. DRY_RUN、重複request_id、名前衝突、種別混在、SHA変更、公式ID不在、GitHub認証不足、403/404/422/429、タイムアウト後再照会、package不一致、Store証拠なし、ディスク上限、中断復帰をモック・実ローカル環境でテストし、CI/実API/実MSIX/公式ID返却を別々に記録する。

具体的な共通JSON入力/出力例と責任分界：
https://github.com/shihuiarenjinba-png/Windows-all-auto/blob/codex/windows-all-auto-integration-20261026/docs/LOCAL_PROVISIONER_ROLE_CHANGE_2026-10-26.md

既存Draft PR #1の命名提案はそのまま残してよいが **create_allowed=false** のままとし、前のRepo新設指示を本番作業に適用しない。main/release、Factory、Windows-all-autoのコードはローカル担当から無断変更しない。認証情報や秘密鍵はGitに置かない。最終的に `docs/LOCAL_PROVISIONER_HANDOFF.md` に作業前後のHEAD、実コミット、テスト件数、実MSIX/Identity試験、返却先、HOLD/依存関係を記録する。
