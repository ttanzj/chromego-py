import urllib.request
import os
import re
from urllib.error import URLError, HTTPError
from collections import defaultdict


def fetch_url(url: str) -> str:
    """读取订阅地址内容"""
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.getcode() == 200:
                return response.read().decode('utf-8', errors='replace')
            else:
                return f"# 【错误】HTTP {response.getcode()} - {url}\n"
    except (URLError, HTTPError) as e:
        return f"# 【错误】无法访问 {url}：{str(e)}\n"
    except Exception as e:
        return f"# 【错误】未知异常 {url}：{str(e)}\n"


def extract_kernel_name(group_title: str) -> str:
    """
    从分组标题中提取内核/协议名称作为文件名
    支持 Clash、Quick、Hysteria1/2、Sing-box、Xray、Juicity 等
    """
    title = group_title.lower().strip()
    # 名称映射表（优先匹配）
    kernel_map = {
        'clash': 'clash',
        'clash.meta': 'clash',
        'quick': 'quick',
        'sing-box': 'sing-box',
        'singbox': 'sing-box',
        'v2ray': 'v2ray',
        'xray': 'xray',
        'hysteria2': 'hysteria2',
        'hysteria 2': 'hysteria2',
        'hy2': 'hysteria2',
        'hysteria1': 'hysteria1',
        'hysteria': 'hysteria1',
        'tuic': 'tuic',
        'trojan': 'trojan',
        'shadowsocks': 'shadowsocks',
        'ss ': 'shadowsocks',
        'ssr': 'shadowsocks',
        'juicity': 'juicity',
        'mieru': 'mieru',
        'naiveproxy': 'naiveproxy',
        'naive': 'naiveproxy',
        'shadowquic': 'shadowquic',
    }
    # 先用映射表精确匹配
    for key, kernel in kernel_map.items():
        if key in title:
            return kernel
    # 正则兜底匹配
    match = re.search(r'(clash|quick|sing-?box|v2ray|xray|hysteria2?|hy2?|hysteria1?|tuic|trojan|shadowsocks|ssr|juicity|mieru|naiveproxy|naive|shadowquic)', title)
    if match:
        name = match.group(1)
        # 名称规范化
        if name in ('singbox', 'sing-box'):
            return 'sing-box'
        elif name.startswith('hysteria2') or name in ('hy2', 'hysteria 2'):
            return 'hysteria2'
        elif name.startswith('hysteria') or name == 'hysteria1':
            return 'hysteria1'
        elif name in ('v2ray', 'xray'):
            return name
        elif name in ('quick', 'juicity', 'mieru', 'naiveproxy', 'naive', 'shadowquic'):
            return name
        return name
    # 最终兜底
    cleaned = re.sub(r'[^a-z0-9]', '', title.split()[0] if title else 'nodes')
    return cleaned or 'nodes'


def sanitize_filename(name: str) -> str:
    """清理文件名非法字符"""
    invalid = '<>:"/\\|?*'
    for char in invalid:
        name = name.replace(char, '_')
    name = name.strip().strip('_')
    return name[:100]


def main():
    input_file = "urls/sources.txt"
    output_dir = "outputs"
   
    if not os.path.exists(input_file):
        print(f"❌ 未找到 {input_file} 文件！")
        return

    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 输出文件夹：{output_dir}/\n")

    # 解析分组
    groups = []
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_group = None
    current_urls = []
    for line in lines:
        stripped = line.strip()
        if stripped == "":
            if current_group and current_urls:
                groups.append((current_group, current_urls[:]))
                current_urls = []
            current_group = None
            continue
        if current_group is None and stripped.startswith('#'):
            current_group = line.rstrip()  # 保留原始标题
            current_urls = []
        else:
            if stripped and not stripped.startswith('#'):
                current_urls.append(stripped)

    if current_group and current_urls:
        groups.append((current_group, current_urls[:]))

    print(f"✅ 共解析到 {len(groups)} 个分组，开始处理...\n")

    total = 0
    kernel_count = {}                    # 处理同名内核序号
    special_contents = defaultdict(str)  # 新增：用于收集 sing-box、quick、naiveproxy、juicity 的内容

    for group_id, urls in groups:
        # 提取内核名
        kernel_name = extract_kernel_name(group_id)
       
        # 处理同名文件序号
        kernel_count[kernel_name] = kernel_count.get(kernel_name, 0) + 1
        suffix = f"_{kernel_count[kernel_name]}" if kernel_count[kernel_name] > 1 else ""
       
        filename = sanitize_filename(kernel_name) + suffix
        output_file = os.path.join(output_dir, f"{filename}.txt")

        print(f"📂 处理分组：{group_id} → {output_file} (内核: {kernel_name})")

        # 收集该分组的所有订阅内容
        group_content = f"# =======================\n"
        group_content += f"# 分组标题: {group_id}\n"
        group_content += f"# 内核类型: {kernel_name}\n"
        group_content += f"# 由 merge_sources.py 自动生成\n"
        group_content += f"# =======================\n\n"

        for url in urls:
            print(f" ⬇️ 下载 → {url}")
            content = fetch_url(url)
            total += 1
            group_content += content + "\n\n"

        # 写入单个内核文件（原逻辑不变）
        with open(output_file, "w", encoding="utf-8") as out:
            out.write(group_content)

        # 新增逻辑：收集需要合并到 s-q-n-j.txt 的内容
        target_kernels = {'sing-box', 'quick', 'naiveproxy', 'juicity'}
        if kernel_name in target_kernels:
            special_contents[kernel_name] += group_content

    # ==================== 新增：生成 s-q-n-j.txt ====================
    sqnj_file = os.path.join(output_dir, "s-q-n-j.txt")
    
    with open(sqnj_file, "w", encoding="utf-8") as f:
        f.write("# =======================\n")
        f.write("# s-q-n-j 合并文件\n")
        f.write("# 顺序：sing-box → quick → naiveproxy → juicity\n")
        f.write("# 由 merge_sources.py 自动生成\n")
        f.write("# =======================\n\n")

        order = ['sing-box', 'quick', 'naiveproxy', 'juicity']
        for kernel in order:
            if special_contents[kernel]:
                f.write(f"\n# ==================== {kernel.upper()} ====================\n\n")
                f.write(special_contents[kernel])
            else:
                f.write(f"\n# ==================== {kernel.upper()} ====================\n")
                f.write("# （无对应订阅内容）\n\n")

    print(f"\n🎉 全部完成！共处理 {total} 个订阅")
    print(f"📁 所有文件已保存至：{output_dir}/")
    print(f"📄 额外生成合并文件：{sqnj_file}")


if __name__ == "__main__":
    main()
