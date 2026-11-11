# tools/vmp —— VMP 验证工具

给「判断 VMP 到底有没有生效」用的两个脚本。都是排查 2026-11-11 那次
`VMP 覆盖率 3/10 → 10/10` 时写的，实测可用。

## measure-startup.sh —— 冷启动耗时

```bash
./measure-startup.sh com.xixin.box .MainActivity 10
# 输出: n=10  min=164  中位数=183.5  mean=186.0  max=208 ms
```

两组配置各跑一次（一组带 `vmp:true`，一组 `vmp:false`），对比中位数。
**次数别低于 8**——样本少会得出相反结论（详见交接文档 §5.4）。

## vmpcheck.py —— 解 `.ncx` 看函数形态

```bash
python3 vmpcheck.py <解出的 libnc.so> <对应 apk>
# 输出: .ncx 明文大小、函数序言统计、是否解出 ncx_vmp.bin
```

原理：`.ncx` 的 RC4 密钥由 APK 签名证书 + `.text` 头部派生，
所以要**同时给 so 和它所属的 apk**（配错会解密出垃圾）。

⚠️ **它给的「判据解读」别全信。**「有/无 VMP 两版都被锁箱」时，
`.ncx` 大小和目标常量搜索都会失效，唯一可靠的是：

| 判据 | 方法 |
|---|---|
| `VmVirtualize` 日志出现过 | 构建时 `RUST_LOG=amice=debug` |
| `.text` / `.rodata` 体积差 | 对照组做减法 |

详见 `docs/so层防御/VMP接入交接-2026-11-11.md` §4.3.1。
