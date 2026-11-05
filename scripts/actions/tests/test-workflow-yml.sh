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

# 「推送自动跑测试」是 2026-11-01 的核心诉求：用户的原话是
# 「推送不就自动跑了吗」——若 on 里没有 push，test job 永远不会被触发，
# 那整套回归检查等于没接。这一条是防回退的关键断言。
assert "push" in trigger, "on 缺 push：推送不会自动跑 test job（回归检查形同虚设）"
assert "pull_request" in trigger, "on 缺 pull_request"
assert "workflow_dispatch" in trigger, "on 缺 workflow_dispatch（出包入口）"

# protect 是出包 job，需要 apk_url/protect_config 必填输入，
# 只能手动触发。push 触发的 run 若也跑它，必然因为空输入而红。
pif = d["jobs"]["protect"].get("if", "")
assert "workflow_dispatch" in pif, \
    "protect job 必须用 if 限制为 workflow_dispatch（否则 push 时因缺输入必然失败）"

inputs = trigger["workflow_dispatch"]["inputs"]
assert set(inputs) == {"apk_url", "protect_config", "dpt_extra_args", "sign",
                       "amice_probe"}, \
    f"inputs 应为 apk_url+protect_config+dpt_extra_args+sign+amice_probe: {list(inputs)}"
assert inputs["protect_config"]["required"] is True
assert inputs["dpt_extra_args"]["required"] is False, "dpt_extra_args 应可选(报错四十三通用通道)"
assert "dpt.jar" in inputs["dpt_extra_args"]["description"], "dpt_extra_args 描述缺用途说明"
# sign(§3.15)：必须是 workflow 独立 input 且默认 false——
# 不能塞进 protect_config(resolve-config 白名单保险丝会 die)，
# 默认 true 会破坏「产出未签名包」的既有契约。
assert inputs["sign"].get("default") is False, "sign 默认必须 false(未签名契约)"
assert inputs["sign"].get("type") == "boolean", "sign 应为 boolean 类型"
# amice_probe（2026-11-05）：Amice 混淆插件探路开关。
# 默认必须 false —— 它要下 848MB bundle，绝不能占每次手动出包的时间。
# 且 protect job 必须在 probe 模式下被排除，否则会因缺 apk_url 空跑。
assert inputs["amice_probe"].get("default") is False, \
    "amice_probe 默认必须 false（848MB 下载不该拖慢正常出包）"
assert inputs["amice_probe"].get("type") == "boolean", "amice_probe 应为 boolean 类型"
assert "amice-probe" in d["jobs"], "缺 amice-probe job"
assert "amice-integrate" in d["jobs"], "缺 amice-integrate job（真实 so 接入验证）"
aif = d["jobs"]["amice-integrate"].get("if", "")
assert "amice_probe" in aif, "amice-integrate job 必须由 inputs.amice_probe 门控"
# 三步锁箱不能合并传参（so-section-lock.py 是互斥分支）——
# 2026-11-05 实测：同时传 --lock-head --strip-meta 会只做二级锁箱，
# .ncx 保持明文 ARM64（熵 5.5），看起来"锁了"实际没锁。
aisteps = "\n".join((s.get("run") or "") for s in d["jobs"]["amice-integrate"]["steps"])
assert "--section .ncx" in aisteps, "amice-integrate 缺一级锁箱（--section .ncx）"
assert "--lock-head" in aisteps, "amice-integrate 缺二级锁箱（--lock-head）"
assert "--strip-meta" in aisteps, "amice-integrate 缺元数据清理"
# 互斥分支：--lock-head 与 --section 不能出现在同一条 python3 调用里
for ln in aisteps.split("\n"):
    if "so-section-lock.py" in ln and "--lock-head" in ln:
        assert "--section" not in ln, \
            "so-section-lock.py 的 --lock-head 与 --section 是互斥分支，不能同传"
apif = d["jobs"]["amice-probe"].get("if", "")
assert "amice_probe" in apif, "amice-probe job 必须由 inputs.amice_probe 门控"
ppif = d["jobs"]["protect"].get("if", "")
assert "amice_probe" in ppif, \
    "protect job 必须排除 amice_probe 模式（否则 probe 时缺 apk_url 空跑变红）"
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
# 冻结模块的专项回归（2026-11-01 补）：inject-loadlib 历史事故最多
assert "scripts/inject/tests/test_inject_loadlib.py" in truns, \
    "test job 缺 inject-loadlib 回归（冻结模块，历史 14 次事故）"
assert "scripts/repack/tests/test_mark_native.py" in truns, \
    "test job 缺 mark-native 回归（冻结模块，历史 11 次事故）"
# 上限 25 分钟：第一/二/三批全部接进来了（so-lock 52 项 + sigcheck 四套）。
# 本地实测合计约 9 分钟，CI 慢些，留 2 倍余量。
# 再大说明该拆 job 了（例如把 so 层单独拆出去并行）。
assert d["jobs"]["test"].get("timeout-minutes", 99) <= 25, \
    "test job 超过 25 分钟，应拆 job 并行（不要把全部套件压在一个 job 里）"

# ── 环境唯一真相：test 与 protect 必须 uses 同一个 composite action ──
# 这条是本仓库最贵的一课：最初 test job 照着 protect job 手工抄环境步骤，
# 连抄 5 次红（漏 pip 依赖 / 漏解压 dex2c / 抄了不存在的 nox tag）。
# 抄一遍 = 制造第二份真相，两边必然漂移。谁再手写环境步骤，这条断言会红。
def _uses(step):
    return step.get("uses", "")

for jname in ("test", "protect"):
    jsteps = d["jobs"][jname]["steps"]
    uses_list = [_uses(s) for s in jsteps]
    assert "./.github/actions/setup-toolchain" in uses_list, \
        f"{jname} job 必须 uses 共用的 setup-toolchain action（不许手写环境步骤）"
    # 环境步骤不得在 job 里手写：解压 dex2c/nox、pip install 都归 action 管
    runs = "\n".join((s.get("run") or "") for s in jsteps)
    for forbidden in ("unzip -qo tools/dex2c.zip", "unzip -qo tools/nox.zip",
                      "pip3 install -r tools/Dex2C/requirements.txt"):
        assert forbidden not in runs, \
            f"{jname} job 里出现了手写的环境步骤 `{forbidden}` —— 应放进 setup-toolchain"
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
