# Recon Header API

指定したドメインに対して、公開情報だけを使って次を診断する FastAPI アプリです。

- DNS 解決結果（プライベート・ローカル・予約済み IP は拒否）
- HTTP セキュリティヘッダー
- TLS バージョン、暗号、証明書期限、発行者、SAN
- HTML とレスポンスヘッダーから推定した CMS

破壊的な探索、ポートスキャン、認証試行、脆弱性の悪用は行いません。自分が所有する、または診断許可を得たドメインだけを指定してください。

## 起動

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

OpenAPI UI は `http://localhost:8000/docs`、ヘルスチェックは `/health` です。

## 診断

```bash
curl -sS http://localhost:8000/v1/scan \
  -H 'content-type: application/json' \
  -d '{"domain":"example.com"}'
```

## テスト

```bash
.venv/bin/pytest
```
