#!/usr/bin/env python3
"""
WAF 绕过模块 - 通过解析 JS 挑战获取 WAF cookies
"""

import re
import subprocess

import httpx


def solve_waf_challenge(domain: str) -> dict | None:
    """获取 WAF cookies（acw_tc, cdn_sec_tc, acw_sc__v2）

    通过以下步骤绕过 WAF:
    1. 访问页面获取 JS 挑战和初始 cookies
    2. 用 Node.js 执行 JS 挑战计算 acw_sc__v2
    3. 返回所有 WAF cookies

    Args:
        domain: 目标域名，如 https://anyrouter.top

    Returns:
        WAF cookies 字典，失败返回 None
    """
    try:
        client = httpx.Client(http2=True, follow_redirects=False, timeout=30.0)
        resp = client.get(
            f'{domain}/login',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            },
        )
        html = resp.text
        initial_cookies = dict(resp.cookies)
        client.close()
    except Exception as e:
        print(f'[FAILED] WAF: Failed to fetch challenge page: {e}')
        return None

    # 提取 arg1
    arg1_match = re.search(r"var arg1='([0-9A-Fa-f]+)'", html)
    if not arg1_match:
        # 没有 WAF 挑战，可能直接通过了
        if initial_cookies:
            print('[INFO] WAF: No JS challenge detected, using initial cookies')
            return initial_cookies
        print('[FAILED] WAF: No challenge found and no cookies received')
        return None

    print(f'[INFO] WAF: JS challenge detected, solving...')

    # 提取 JS 代码
    script_match = re.search(r'<script>(.*?)</script>', html, re.DOTALL)
    if not script_match:
        print('[FAILED] WAF: Cannot extract JS code')
        return None

    # 用 Node.js 执行 JS 挑战
    js_code = script_match.group(1)
    mock_js = (
        "var document = {cookie: '', location: {reload: function(){}}};\n"
        + js_code
        + "\nconsole.log(document.cookie);"
    )

    try:
        result = subprocess.run(
            ['node', '-e', mock_js],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f'[FAILED] WAF: Node.js error: {result.stderr[:200]}')
            return None
    except FileNotFoundError:
        print('[FAILED] WAF: Node.js not found, please install Node.js')
        return None
    except subprocess.TimeoutExpired:
        print('[FAILED] WAF: Node.js execution timed out')
        return None

    cookie_match = re.search(r'acw_sc__v2=([0-9a-fA-F]+)', result.stdout.strip())
    if not cookie_match:
        print(f'[FAILED] WAF: Cannot parse acw_sc__v2 from Node output')
        return None

    waf_cookies = {**initial_cookies, 'acw_sc__v2': cookie_match.group(1)}
    print(f'[SUCCESS] WAF: Got {len(waf_cookies)} cookies')
    return waf_cookies
