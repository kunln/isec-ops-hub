#!/usr/bin/env python3
"""
验证配置文件自动初始化功能

用法：
    python tests/verify_config_init.py
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path


def verify_config_init():
    """在临时目录中验证配置初始化功能"""
    print("🧪 验证配置文件自动初始化功能\n")
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = Path(tmpdir)
        os.chdir(test_dir)
        
        # 步骤 1: 创建 .flocks 目录和示例文件
        print("📁 步骤 1: 创建 .flocks 目录和示例文件")
        flocks_dir = test_dir / ".flocks"
        flocks_dir.mkdir()
        
        # 创建示例文件
        config_example = flocks_dir / "flocks.json.example"
        config_example.write_text('{\n  "provider": {},\n  "mcp": {}\n}')
        print(f"   ✓ 创建 {config_example.name}")

        mcp_example = flocks_dir / "mcp_list.json.example"
        mcp_example.write_text('{\n  "version": "1.0.0",\n  "categories": {},\n  "servers": []\n}')
        print(f"   ✓ 创建 {mcp_example.name}")
        
        secret_example = flocks_dir / ".secret.json.example"
        secret_example.write_text('{}')
        print(f"   ✓ 创建 {secret_example.name}\n")
        
        # 步骤 2: 检查文件不存在
        print("📋 步骤 2: 检查配置文件不存在")
        config_file = flocks_dir / "flocks.json"
        mcp_file = flocks_dir / "mcp_list.json"
        secret_file = flocks_dir / ".secret.json"
        
        if not config_file.exists():
            print("   ✓ flocks.json 不存在")
        else:
            print("   ✗ flocks.json 已存在（测试失败）")
            return False
            
        if not secret_file.exists():
            print("   ✓ .secret.json 不存在\n")
        else:
            print("   ✗ .secret.json 已存在（测试失败）")
            return False

        if not mcp_file.exists():
            print("   ✓ mcp_list.json 不存在\n")
        else:
            print("   ✗ mcp_list.json 已存在（测试失败）")
            return False
        
        # 步骤 3: 运行初始化函数
        print("🚀 步骤 3: 运行配置初始化函数")
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from flocks.config.config_writer import ensure_config_files
        
        ensure_config_files()
        print("   ✓ ensure_config_files() 执行完成\n")
        
        # 步骤 4: 验证文件已创建
        print("✅ 步骤 4: 验证文件已创建")
        
        if config_file.exists():
            content = config_file.read_text()
            print(f"   ✓ flocks.json 已创建")
            print(f"   内容: {content[:50]}...")
        else:
            print("   ✗ flocks.json 未创建（测试失败）")
            return False
        
        if secret_file.exists():
            content = secret_file.read_text()
            print(f"   ✓ .secret.json 已创建")
            print(f"   内容: {content[:50]}...")
        else:
            print("   ✗ .secret.json 未创建（测试失败）")
            return False

        if mcp_file.exists():
            content = mcp_file.read_text()
            print(f"   ✓ mcp_list.json 已创建")
            print(f"   内容: {content[:50]}...")
        else:
            print("   ✗ mcp_list.json 未创建（测试失败）")
            return False
        
        print("\n" + "="*60)
        print("🎉 所有测试通过！配置文件自动初始化功能正常工作。")
        print("="*60)
        return True


if __name__ == "__main__":
    success = verify_config_init()
    sys.exit(0 if success else 1)
