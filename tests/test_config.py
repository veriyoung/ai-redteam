"""
测试配置加载器 (config.py)
"""
import os
import tempfile
import pytest
from ai_redteam.models.types import VulnCategory, TestRunConfig
from ai_redteam.runners.config import (
    _parse_categories, load_config, load_config_dict, DEFAULT_CONFIG,
)


class TestParseCategories:
    """类别解析测试"""

    def test_valid_categories(self):
        result = _parse_categories(["prompt_injection", "jailbreak"])
        assert len(result) == 2
        assert result[0] == VulnCategory.PROMPT_INJECTION
        assert result[1] == VulnCategory.JAILBREAK

    def test_mixed_valid_invalid(self):
        """混入无效类别时自动跳过，不崩溃"""
        result = _parse_categories(["prompt_injection", "invalid_cat", "jailbreak"])
        assert len(result) == 2
        assert VulnCategory.PROMPT_INJECTION in result
        assert VulnCategory.JAILBREAK in result

    def test_all_invalid_returns_default(self):
        """全部无效时返回默认类别"""
        result = _parse_categories(["bad1", "bad2"])
        assert len(result) > 0

    def test_empty_list(self):
        """空列表返回默认"""
        result = _parse_categories([])
        assert len(result) > 0

    def test_non_string_items_skipped(self):
        """非字符串项被跳过"""
        result = _parse_categories(["prompt_injection", 123, None])
        assert len(result) == 1
        assert result[0] == VulnCategory.PROMPT_INJECTION


class TestLoadConfigDict:
    """字典配置加载测试"""

    def test_basic_dict(self):
        data = {
            "target": {"provider": "mock", "model": "mock"},
            "categories": ["prompt_injection"],
        }
        config = load_config_dict(data)
        assert isinstance(config, TestRunConfig)
        assert config.target["provider"] == "mock"
        assert len(config.categories) == 1

    def test_invalid_category_in_dict(self):
        """字典中包含无效类别时不崩溃"""
        data = {
            "target": {"provider": "mock", "model": "mock"},
            "categories": ["invalid_cat"],
        }
        config = load_config_dict(data)
        assert isinstance(config, TestRunConfig)
        assert len(config.categories) > 0

    def test_presets_passed_through(self):
        data = {
            "target": {"provider": "mock", "model": "mock"},
            "categories": ["prompt_injection"],
            "presets": ["owasp"],
        }
        config = load_config_dict(data)
        assert config.presets == ["owasp"]


class TestLoadConfig:
    """YAML文件配置加载测试"""

    def test_load_valid_yaml(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("""
name: "测试配置"
target:
  provider: mock
  model: mock
categories:
  - prompt_injection
  - jailbreak
presets:
  - owasp
""")
            f.flush()

        try:
            config = load_config(f.name)
            assert config.name == "测试配置"
            assert config.target["provider"] == "mock"
            assert len(config.categories) == 2
        finally:
            os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """不存在的文件返回默认配置"""
        config = load_config("/nonexistent/path.yaml")
        assert isinstance(config, TestRunConfig)

    def test_auto_switch_to_mock_when_no_api_key(self):
        """无API密钥时自动切换到Mock模式"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("""
name: "测试"
target:
  provider: openai
  model: gpt-4o-mini
  api_key: ""
categories:
  - prompt_injection
""")
            f.flush()

        try:
            config = load_config(f.name)
            assert config.target["provider"] == "mock"
            assert config.target["model"] == "mock"
        finally:
            os.unlink(f.name)

    def test_invalid_category_in_yaml(self):
        """YAML中包含无效类别时不崩溃"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write("""
name: "测试"
target:
  provider: mock
  model: mock
categories:
  - invalid_category
  - prompt_injection
""")
            f.flush()

        try:
            config = load_config(f.name)
            assert isinstance(config, TestRunConfig)
            assert VulnCategory.PROMPT_INJECTION in config.categories
        finally:
            os.unlink(f.name)