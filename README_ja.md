# Lvau

> ローカルファイルを暗号化し、形式や公開情報をあとから確認できる暗号化カプセル。

Lvauは、ローカルファイル暗号化のための実験的なRustワークスペースです。CLI、再利用可能な暗号ライブラリ、バージョン管理された`.lvau`形式、ネイティブGUI、自己展開アーカイブの試作を含みます。現在のリリースは**0.5.0**です。

[English](README.md) · 日本語

[![CI](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml/badge.svg)](https://github.com/lasder-ca/lvau/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> Lvauは第三者による正式なセキュリティ監査を完了しておらず、1.0より前に形式が変わる可能性があります。重要なデータへ使う前に、[SECURITY.md](SECURITY.md)と[脅威モデル](docs/THREAT_MODEL.md)を確認してください。

## クイックスタート

```sh
lvau-cli encrypt --password --in-file secret.txt --out-file secret.txt.lvau
lvau-cli inspect --in-file secret.txt.lvau
lvau-cli verify --password --in-file secret.txt.lvau
lvau-cli decrypt --password --in-file secret.txt.lvau --out-file secret.restored.txt
```

パスワード入力は画面に表示されません。ローカルの自動処理では、読み取り権限を制限したパスワードファイルを使います。

```sh
printf '%s' '十分に強いパスフレーズへ置換' > password.txt
chmod 600 password.txt
lvau-cli encrypt \
  --in-file secret.txt \
  --out-file secret.txt.lvau \
  --password-file password.txt
```

Windowsでは、Lvauを実行するアカウントだけが読めるようにパスワードファイルのACLを制限してください。広すぎる権限を自動で拒否する確認はUnix環境だけで動作します。パスワード、秘密鍵、シード、復旧共有、認証情報をGitへ追加しないでください。

## Lvauでできること

| 機能 | 状態 |
|---|---|
| XChaCha20-Poly1305、Argon2id、HKDF-SHA256によるパスワード暗号化 | テスト可能 |
| ストリーミング暗号化と認証付き検証 | テスト可能 |
| ペイロードを復号しない公開情報の検査 | テスト可能 |
| 暗号化された目録を持つパスワード保護ディレクトリバンドル | テスト可能 |
| Ed25519による著者署名 | テスト可能 |
| 検査、検証、事前確認、レポート、ポリシー確認のJSON出力 | スキーマversion 1 |
| ハイブリッド受信者暗号化と多段プロファイル | 実験的 |
| 承認メタデータ、復旧機能、GUI、自己展開アーカイブ | 実験的 |

ポリシー確認は実験的な補助機能です。`decrypt`や`bundle extract`では自動実行されないため、復号や展開の前に条件を満たす必要がある場合は、`policy lint`または`preflight`を別の手順として実行してください。

## 自動処理とNelo連携

自動処理向けJSONは、実装済みのコマンドでバージョン付きの共通形式を使います。正確な対応範囲と互換性ルールは[JSON出力契約](docs/JSON_OUTPUT.md)を確認してください。

[Nelo](https://github.com/lasder-ca/Nelo)は、HTTPリクエストの寿命に`lvau-cli`プロセスを結び付けられます。連携例では、リクエスト中断時に暗号化処理を終了し、アップロードサイズを制限し、リクエスト所有の一時平文を削除します。[Nelo連携ガイド](docs/integrations/NELO.md)を確認してください。

## ソースからビルド

```sh
git clone https://github.com/lasder-ca/lvau.git
cd lvau
cargo build --locked --workspace --release
```

実行ファイルは`target/release/`へ生成されます。正確なコマンドオプションは`lvau-cli <command> --help`で確認してください。

## セキュリティ上の境界

Lvauが保護できるのは、パスワード、秘密鍵、利用端末が安全に保たれている場合のペイロードの機密性と完全性です。マルウェア、キーロガー、侵害されたOS、弱いパスワード、盗まれた鍵、悪意のある出力先、すべての認証情報の紛失からは保護できません。

envelopeには、方式名、KDF設定、受信者スロット、nonce、平文のおおよその大きさ、任意の公開ラベルが記録されます。バンドル内のパスとファイル情報は既定で暗号化されます。署名、承認、リリース、復旧に関する項目は別の注釈であり、明示的な検証と解釈が必要です。

形式v2/v1の構造と移行方法は[形式ドキュメント](docs/FORMAT.md)を確認してください。

## ワークスペース

| クレート | 役割 |
|---|---|
| `lvau-protocol` | envelopeと目録のシリアライズ型 |
| `lvau-core` | 暗号処理、解析、ファイル、バンドル、署名、ポリシー、復旧 |
| `lvau-cli` | コマンドラインと自動処理向け出力 |
| `lvau-gui` | `lvau-core`を使う実験的なネイティブGUI |
| `lvau-stub` | 実験的な自己展開アーカイブ |

## 開発

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --workspace --release
cargo tree --duplicates
cargo run --locked --quiet --package lvau-cli -- self-test
```

[CONTRIBUTING.md](CONTRIBUTING.md)、[ロードマップ](docs/ROADMAP.md)、[変更履歴](CHANGELOG.md)も確認してください。機密性の高い脆弱性は公開Issueへ書かず、[SECURITY.md](SECURITY.md)の手順で報告してください。

## ライセンス

[MIT License](LICENSE)で公開しています。
