import brut.androlib.smali.SmaliBuilder;
import com.android.tools.smali.dexlib2.writer.builder.DexBuilder;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.Opcodes;
import java.io.File;

/**
 * 独立验证器：只跑 smali 汇编（dexlib2），不碰资源/aapt2。
 * 等价于 apktool b 里的 smali 那一步 —— 用来证明生成的 smali 语法合法。
 *
 * 用法: java -cp apktool.jar:. VerifySmali <smali目录> <输出dex> [apiLevel]
 */
public class VerifySmali {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("用法: VerifySmali <smali目录> <输出dex> [apiLevel]");
            System.exit(2);
        }
        int api = args.length >= 3 ? Integer.parseInt(args[2]) : 30;
        File root = new File(args[0]);
        java.util.List<File> files = new java.util.ArrayList<File>();
        collect(root, files);
        if (files.isEmpty()) {
            System.err.println("❌ 目录下没有 .smali: " + root);
            System.exit(1);
        }
        java.util.Collections.sort(files);

        DexBuilder dexBuilder = new DexBuilder(new Opcodes(api));
        SmaliBuilder builder = new SmaliBuilder(api);
        int ok = 0;
        for (File f : files) {
            if (builder.buildFile(f, dexBuilder)) ok++;
        }
        File out = new File(args[1]);
        if (out.exists()) out.delete();
        dexBuilder.writeTo(new FileDataStore(out));
        System.out.println("✅ 汇编 " + ok + "/" + files.size() + " 个 smali → "
                + args[1] + " (" + out.length() + " B)");
        if (ok != files.size()) {
            System.err.println("❌ 有 " + (files.size() - ok) + " 个文件汇编失败");
            System.exit(1);
        }
    }

    private static void collect(File dir, java.util.List<File> out) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        java.util.Arrays.sort(kids);
        for (File k : kids) {
            if (k.isDirectory()) collect(k, out);
            else if (k.getName().endsWith(".smali")) out.add(k);
        }
    }
}
