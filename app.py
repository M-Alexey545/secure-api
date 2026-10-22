import sqlite3
import html
import os
import datetime
from functools import wraps

import jwt
import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)

# 教学示例用固定密钥；生产环境请通过环境变量设置
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me-please")
TOKEN_EXPIRE_HOURS = 1


# ---------------- 数据库工具 ----------------
def get_db():
    """每次请求新建连接，避免 SQLite 多线程问题。"""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- JWT 认证中间件 ----------------
def token_required(f):
    """校验 Authorization: Bearer <token>，通过后把 payload 放入 request.jwt_payload。"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing or malformed token"}), 401

        token = auth.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        request.jwt_payload = payload
        return f(*args, **kwargs)

    return wrapper


# ---------------- 端点 1：POST /auth/login ----------------
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "invalid credentials"}), 401

    conn = get_db()
    try:
        # 参数化查询：用户输入只作为数据，不拼接到 SQL 字符串中
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        # 统一错误信息，避免账号枚举
        return jsonify({"error": "invalid credentials"}), 401

    stored_hash = row["password_hash"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8")

    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify({"error": "invalid credentials"}), 401

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": row["username"],
        "iat": now,
        "exp": now + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token, "token_type": "Bearer", "expires_in": TOKEN_EXPIRE_HOURS * 3600})


# ---------------- 端点 2：GET /api/data（受保护） ----------------
@app.route("/api/data", methods=["GET"])
@token_required
def get_data():
    conn = get_db()
    try:
        rows = conn.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    finally:
        conn.close()

    # 输出转义：防止用户名中的 < > & " ' 被当作 HTML 解析
    users = [{"id": r["id"], "username": html.escape(r["username"])} for r in rows]
    return jsonify({"users": users, "count": len(users)})


# ---------------- 端点 3：GET /api/me（受保护，自行设计） ----------------
@app.route("/api/me", methods=["GET"])
@token_required
def me():
    payload = request.jwt_payload
    username = payload.get("sub", "")
    return jsonify({
        "current_user": html.escape(str(username)),
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    })


# ---------------- 健康检查（可选，方便回归测试） ----------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)