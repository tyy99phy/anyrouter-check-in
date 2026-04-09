#!/usr/bin/env python3
"""
自动登录模块 - 使用账号密码获取 session cookie
"""

import httpx


def auto_login(domain: str, username: str, password: str, waf_cookies: dict) -> dict | None:
    """使用账号密码登录，返回认证信息

    Args:
        domain: 目标域名
        username: 用户名
        password: 密码
        waf_cookies: WAF cookies

    Returns:
        包含 session, user_id, api_user 的字典，失败返回 None
    """
    client = httpx.Client(http2=True, timeout=30.0)
    client.cookies.update(waf_cookies)

    try:
        resp = client.post(
            f'{domain}/api/user/login',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/plain, */*',
                'Referer': f'{domain}/login',
                'Origin': domain,
            },
            json={'username': username, 'password': password},
        )

        # 检查是否被 WAF 二次拦截
        if '<script>' in resp.text and 'arg1' in resp.text:
            print(f'[FAILED] {username}: WAF blocked login API request')
            return None

        data = resp.json()
        if not data.get('success'):
            msg = data.get('message', 'Unknown error')
            print(f'[FAILED] {username}: Login failed - {msg}')
            return None

        session = resp.cookies.get('session')
        if not session:
            print(f'[FAILED] {username}: Login succeeded but no session cookie received')
            return None

        user_data = data.get('data', {})
        user_id = user_data.get('id')

        print(f'[SUCCESS] {username}: Login successful (user_id={user_id})')

        return {
            'session': session,
            'user_id': str(user_id),
            'cookies': {**waf_cookies, 'session': session},
        }

    except Exception as e:
        print(f'[FAILED] {username}: Login error - {str(e)[:100]}')
        return None
    finally:
        client.close()
