"""
环境变量安全验证

对齐 OpenClaw bash-tools.exec.ts 中的 validateHostEnv：
- 在非沙箱执行路径上阻止危险环境变量
- 阻止 PATH 修改
"""

# 已知危险环境变量
DANGEROUS_HOST_ENV_VARS = frozenset([
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "RUBYLIB",
    "PERL5LIB",
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
    "IFS",
    "SSLKEYLOGFILE",
])

DANGEROUS_HOST_ENV_PREFIXES = ("DYLD_", "LD_")


def validate_host_env(env: dict[str, str]) -> None:
    """
    验证宿主机执行的环境变量安全性。

    Raises:
        ValueError: 存在危险环境变量
    """
    for key in env:
        upper_key = key.upper()

        # 检查危险前缀
        for prefix in DANGEROUS_HOST_ENV_PREFIXES:
            if upper_key.startswith(prefix):
                raise ValueError(
                    f"Security Violation: Environment variable '{key}' "
                    f"is forbidden during host execution."
                )

        # 检查已知危险变量
        if upper_key in DANGEROUS_HOST_ENV_VARS:
            raise ValueError(
                f"Security Violation: Environment variable '{key}' "
                f"is forbidden during host execution."
            )

        # 阻止 PATH 修改
        if upper_key == "PATH":
            raise ValueError(
                "Security Violation: Custom 'PATH' variable "
                "is forbidden during host execution."
            )
