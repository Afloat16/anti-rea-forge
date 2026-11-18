#!/usr/bin/env python3
"""Render the two README architecture figures as deterministic, editable SVG."""
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COPY = {
    "en": {
        "title": "A release is a boundary.",
        "subtitle": "Keep private material separate. Verify the bytes you ship. Authorize sensitive use.",
        "labels": ["01  TRUSTED BUILD", "02  PUBLIC DISTRIBUTION", "03  AUTHORIZED USE"],
        "titles": ["Separate & inspect", "Ship verified artifacts", "Authenticate & open"],
        "rows": [
            [("PRIVATE INPUTS", ["Source, symbols and selected data", "External keys stay outside the build output"]),
             ("BUILD TRANSFORMS", ["Split maps and private debug sections", "Seal selected assets or VM instructions"]),
             ("RELEASE GATE", ["Bounded format + disclosure checks", "Full inventory, key checks, final recheck"])],
            [("APPLICATION", ["Public code + authenticated ciphertext", "Required ABI and runtime behavior retained"]),
             ("SIGNED MANIFEST", ["Exact paths, sizes and file hashes", "Version and product bound to the signature"]),
             ("PUBLICATION RULE", ["Recognized unsupported format or ambiguity?", "Stop the release and report the reason."])],
            [("INDEPENDENT KEY", ["Check product / release / purpose context", "Authenticate before exposing plaintext"]),
             ("NATIVE LIFETIME", ["Guarded buffers and explicit clearing", "Authorized memory remains observable"]),
             ("SENSITIVE OPERATIONS", ["Trusted service verifies scoped capability", "Expiry and replay checks before admission"])],
        ],
        "footerlabel": "TRUSTED ISSUER / PRIVATE STORAGE",
        "footers": ["Private source maps + symbols", "External keys + signing authority", "Authenticated subject + replay state"],
        "note": "Trust boundary: a public client, target-supplied notice or patched local check cannot grant server authority.",
    },
    "zh-CN": {
        "title": "把发布边界，变成保护边界。",
        "subtitle": "私有资料独立保存 · 发布字节完整核对 · 敏感操作由可信端授权",
        "labels": ["01  可信构建", "02  公开分发", "03  授权使用"],
        "titles": ["分离敏感内容，检查产物", "发布经过验证的文件", "先认证，再开放数据"],
        "rows": [
            [("私有输入", ["源代码、符号与选定的数据", "外部密钥保持在发布目录之外"]),
             ("构建处理", ["分离 source map 与私有调试信息", "封装选定资产或 VM 指令"]),
             ("发布门禁", ["有界格式检查与泄露检查", "完整清单、密钥检查、最终复核"])],
            [("应用产物", ["公开代码与经过认证的密文", "保留必要 ABI 和运行行为"]),
             ("签名清单", ["精确绑定路径、大小和文件哈希", "签名同时绑定产品与版本"]),
             ("发布规则", ["已识别的未支持格式、变化或歧义？", "阻止发布，并给出明确原因。"])],
            [("独立密钥", ["核对产品、版本与用途上下文", "认证成功后才开放明文"]),
             ("原生生命周期", ["受保护缓冲区与显式清理", "授权进程中的明文仍可被观察"]),
             ("敏感操作", ["可信服务验证限定范围的能力凭证", "进入处理函数前核对过期与重放"])],
        ],
        "footerlabel": "可信签发方 / 私有存储",
        "footers": ["私有 source map 与符号", "独立密钥与签名权限", "已认证身份与重放状态"],
        "note": "信任边界：公开客户端、目标文件中的声明、被修改的本地校验，都不能授予服务端权限。",
    },
}


def render(language: str) -> str:
    c = COPY[language]
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="790" viewBox="0 0 1280 790" role="img" aria-labelledby="title desc">',
             f'<title id="title">{escape(c["title"])}</title>',
             f'<desc id="desc">{escape(c["subtitle"] + " " + c["note"])}</desc>',
             '<defs><linearGradient id="background" x2="1" y2="1"><stop stop-color="#101d32"/><stop offset="1" stop-color="#080f1d"/></linearGradient>',
             '<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10" fill="none" stroke="#76d9cb" stroke-width="1.7"/></marker></defs>',
             '<rect width="1280" height="790" rx="24" fill="url(#background)"/>',
             '<g font-family="Inter, Noto Sans CJK SC, Noto Sans, Arial, sans-serif">']

    def text(x, y, value, size=20, color="#dce7f6", weight=400, extra=""):
        parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" {extra}>{escape(value)}</text>')

    text(48, 43, "ANTI-REA FORGE  /  ARCHITECTURE", 15, "#76d9cb", 700, 'letter-spacing="2"')
    text(48, 94, c["title"], 37, "#f5f8ff", 700)
    text(48, 130, c["subtitle"], 19, "#aebfd6")
    for i, x in enumerate((48, 456, 864)):
        color = ("#76d9cb", "#8db8ff", "#d3adff")[i]
        text(x, 178, c["labels"][i], 16, color, 700, 'letter-spacing="1"')
        parts.append(f'<rect x="{x}" y="196" width="368" height="366" rx="18" fill="#142237" stroke="#31435e"/>')
        parts.append(f'<rect x="{x+24}" y="220" width="36" height="4" rx="2" fill="{color}"/>')
        text(x+24, 259, c["titles"][i], 23, "#f2f6ff", 700)
        for j, (label, lines) in enumerate(c["rows"][i]):
            y = 300 + j*88
            text(x+24, y, label, 14, color, 700, 'letter-spacing="0.8"')
            for k, line in enumerate(lines):
                text(x+24, y+27+k*24, line, 16, "#c7d4e7")
        if i < 2:
            parts.append(f'<path d="M{x+375} 387h26" fill="none" stroke="#76d9cb" stroke-width="2" marker-end="url(#arrow)"/>')
    # A separate lower band keeps private keys visually outside public artifacts.
    parts.append('<path d="M1048 614v-37" fill="none" stroke="#76d9cb" stroke-width="2" stroke-dasharray="5 5" marker-end="url(#arrow)"/>')
    parts.append('<rect x="48" y="614" width="1184" height="103" rx="16" fill="#102b31" stroke="#32615f"/>')
    text(72, 646, c["footerlabel"], 15, "#76d9cb", 700, 'letter-spacing="1"')
    for x, label in zip((72, 476, 880), c["footers"]):
        parts.append(f'<circle cx="{x+4}" cy="678" r="4" fill="#76d9cb"/>')
        text(x+18, 685, label, 18, "#e1f3ef")
    text(48, 755, c["note"], 16, "#aebfd6")
    parts.extend(['</g>', '</svg>'])
    return "\n".join(parts) + "\n"


if __name__ == "__main__":
    target = ROOT / "docs/images"
    target.mkdir(parents=True, exist_ok=True)
    for language in COPY:
        (target / f"architecture-{language}.svg").write_text(render(language), encoding="utf-8")
