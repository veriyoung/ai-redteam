"""
图片生成工具 — 将攻击文字渲染为 base64 PNG 图片
用于多模态模型的图片注入攻击测试
"""
import base64
import io
from typing import Optional


def generate_attack_image(text: str, width: int = 800, height: int = 400) -> Optional[str]:
    """将攻击文字渲染为白色背景黑色文字的 PNG 图片，返回 base64 字符串。

    Args:
        text: 要嵌入图片的攻击文字
        width: 图片宽度（像素），默认 800
        height: 图片高度（像素），默认 400

    Returns:
        base64 编码的 PNG 图片字符串；Pillow 不可用时返回 None
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return None

    img = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(img)

    font = None
    for size in (20, 18, 16, 14):
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size)
            break
        except (OSError, IOError):
            continue

    lines = _wrap_text(text, width // (font.size if font else 14) if font else 50)
    y = 20
    for line in lines:
        draw.text((10, y), line, fill="black", font=font)
        y += (font.size if font else 14) + 6

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def _wrap_text(text: str, max_chars_per_line: int) -> list:
    """简单文字换行"""
    lines = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        words = paragraph.split(" ")
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 <= max_chars_per_line:
                current_line = (current_line + " " + word).strip()
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        if current_line:
            lines.append(current_line)
    return lines
