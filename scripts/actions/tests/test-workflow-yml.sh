#!/bin/bash
# protect-modules.yml 结构自检（无 yamllint 环境下的轻量校验）：
# 1) python3 yaml 模块可解析（PyYAML 可用时）
# 2) grep 断言关键结构：inputs 只剩 apk_url + protect_config；mapfile 过滤空行；无旧 inputs 残留
set -u
# 仓库根 = tests → actions → scripts → 根
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)" || exit 1
cd "$ROOT" || exit 1
YML=.github/workflows/protect-modules.yml
fail=0

if python3 -c "import yaml" 2>/dev/null; then
  python3 - "$YML" <<'EOF' || fail=1
import sys, yaml
d = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
# PyYAML 把裸 on 解析成布尔 True 键（YAML 1.1），两种键都接受
trigger = d.get("on", d.get(True, {}))
inputs = trigger["workflow_dispatch"]["inputs"]
assert set(inputs) == {"apk_url", "protect_config", "dpt_extra_args", "sign"}, \
    f"inputs 应为 apk_url+protect_config+dpt_extra_args+sign: {list(inputs)}"
assert inputs["protect_config"]["required"] is True
assert inputs["dpt_extra_args"]["required"] is False, "dpt_extra_args 应可选(报错四十三通用通道)"
assert "dpt.jar" in inputs["dpt_extra_args"]["description"], "dpt_extra_args 描述缺用途说明"
# sign(§3.15)：必须是 workflow 独立 input 且默认 false——
# 不能塞进 protect_config(resolve-config 白名单保险丝会 die)，
# 默认 true 会破坏「产出未签名包」的既有契约。
assert inputs["sign"].get("default") is False, "sign 默认必须 false(未签名契约)"
assert inputs["sign"].get("type") == "boolean", "sign 应为 boolean 类型"
steps = d["jobs"]["protect"]["steps"]
names = [s.get("name", "") for s in steps]
assert any("resolve-config.py" in (s.get("run") or "") for s in steps), "缺解析 step"
assert not any("勾选前置校验" in n for n in names), "旧前置校验 step 应删除"
assert not any("生成 Dex2C 规则" in n for n in names), "旧规则生成 step 应删除"

# ── 回归 job（2026-11-01 新增）──────────────────────────────────
# CI 此前不跑任何测试，导致 test-workflow-yml.sh / check-schema.py 红了几个月
# 无人知晓。这里钉住"回归 job 存在且真的在跑断言"，防止它被顺手删掉。
assert "test" in d["jobs"], "缺 test job（回归检查；见 yml 头注）"
tjobs = d["jobs"]["test"]["steps"]
truns = "\n".join((s.get("run") or "") for s in tjobs)
for must in ("test-docs-paths.py", "check-schema.py",
             "test-resolve-config.py", "test-workflow-yml.sh"):
    assert must in truns, f"test job 缺 {must}（回归防线被削弱）"
# 第二批（2026-11-01）：stringenc/anti-diff/packer，不需要 nox/NDK
for must in ("scripts/anti-diff/tests/test-smoke.sh",
             "scripts/packer/tests/test-packer.sh",
             "scripts/string-enc/tests/test-encrypt-smoke.sh",
             "scripts/string-enc/tests/test-structure-resume.sh",
             "scripts/string-enc/tests/test-stub-randomize.sh",
             "scripts/string-enc/tests/test-keystream-crosscheck.sh",
             "scripts/string-enc/tests/test-link-dex2c.sh"):
    assert must in truns, f"test job 缺第二批套件 {must}（回归防线被削弱）"
# 上限 15 分钟：第一批秒级 + 第二批（stringenc/anti-diff/packer，本地约 4 分钟）
# 留 2 倍余量。再大说明把 11 分钟的重型套件（需 nox/NDK）也塞进来了，应另开 job。
assert d["jobs"]["test"].get("timeout-minutes", 99) <= 15, \
    "test job 必须保持轻量（≤15 分钟），重型套件应另开 job"
print("yaml OK:", list(inputs))
EOF
else
  echo "(PyYAML 不可用，跳过 yaml 解析，走 grep 断言)"
fi

grep -q 'INPUT_PROTECT_CONFIG: ${{ inputs.protect_config }}' "$YML" || { echo "❌ 缺 env 中转"; fail=1; }
grep -q 'INPUT_DPT_EXTRA_ARGS: ${{ inputs.dpt_extra_args }}' "$YML" || { echo "❌ 缺 dpt_extra_args env 中转(报错四十三通用通道)"; fail=1; }
grep -F -- '--dpt-extra-args' "$YML" >/dev/null || { echo "❌ 未向 protect.sh 传 --dpt-extra-args"; fail=1; }
# zipalign 必须在 apksigner 之前（签完再对齐会破坏签名，§3.15.4）
# 用实际命令做锚，不用裸关键词：文件里有 "zipalign 必须在 apksigner 之前"
# 这类注释行，裸 grep 会命中注释导致假红/假绿。
if grep -q 'apksigner sign' "$YML"; then
  za=$(grep -n 'zipalign -f' "$YML" | head -1 | cut -d: -f1)
  as=$(grep -n 'apksigner sign' "$YML" | head -1 | cut -d: -f1)
  if [ -z "$za" ]; then
    echo "❌ 缺 zipalign -f 实际调用（签名前必须对齐）"; fail=1
  elif [ "$za" -ge "$as" ]; then
    echo "❌ zipalign($za) 必须在 apksigner sign($as) 之前"; fail=1
  fi
fi
grep -q 'mapfile -t ARGS < <(grep -v .\^$.\? schema_rules/args.txt)' "$YML" 2>/dev/null || \
  grep -F 'grep -v' "$YML" | grep -q 'args.txt' || { echo "❌ mapfile 未过滤空行（§10.2）"; fail=1; }
grep -F '"${ARGS[@]}"' "$YML" >/dev/null || { echo "❌ ARGS 未用引用展开"; fail=1; }
for legacy in inputs.sigcheck inputs.dex2c_rules inputs.string_rules inputs.lightobf inputs.packer inputs.antidiff inputs.envcheck; do
  grep -q "$legacy" "$YML" && { echo "❌ 旧 input 残留: $legacy"; fail=1; }
done
[[ $fail -eq 0 ]] && echo "protect-modules.yml 自检通过"
exit $fail
