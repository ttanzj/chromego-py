import re
from pathlib import Path
from collections import defaultdict

def extract_subscription_urls(bat_content: str) -> list[str]:
    """从 .bat 文件中提取订阅地址（yaml/json/yml）"""
    urls = []
    pattern = re.compile(r'https?://[^\s<>"\']+\.(?:yaml|json|yml)', re.IGNORECASE)
    
    matches = pattern.findall(bat_content)
    for match in matches:
        url = match.strip('"\' ')
        if url.startswith(('http://', 'https://')):
            urls.append(url)
    
    # 单个 bat 内去重
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


def process_folder(top_folder: str, root_dir: Path) -> dict:
    """处理单个客户端文件夹，返回该文件夹的分组结果"""
    groups = defaultdict(list)
    top_path = root_dir / top_folder
    
    if not top_path.exists() or not top_path.is_dir():
        print(f"⚠️  文件夹不存在: {top_folder}/")
        return {}
    
    print(f"\n开始处理 {top_folder} ...")
    
    for ip_update_dir in top_path.rglob("ip_Update"):
        if not ip_update_dir.is_dir():
            continue
            
        group_name = ip_update_dir.parent.name
        bat_files = list(ip_update_dir.glob("*.bat"))
        
        if not bat_files:
            continue
            
        print(f"  → 处理 {top_folder}/{group_name}/ip_Update/  ({len(bat_files)} 个 .bat 文件)")
        
        for bat_file in bat_files:
            try:
                content = bat_file.read_text(encoding="utf-8", errors="ignore")
                urls = extract_subscription_urls(content)
                if urls:
                    groups[group_name].extend(urls)
            except Exception as e:
                print(f"    读取失败 {bat_file.name}: {e}")
    
    # 每个分组内部去重
    final_groups = {}
    for group_name, url_list in groups.items():
        seen = set()
        unique_urls = []
        for url in url_list:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    return final_groups


def write_sources_file(groups: dict, filename: Path):
    """写入单个 sources 文件"""
    with open(filename, "w", encoding="utf-8", newline="\n") as f:
        first_group = True
        for group_name in sorted(groups.keys()):
            if not first_group:
                f.write("\n")
            f.write(f"# {group_name}\n")
            for url in groups[group_name]:
                f.write(url + "\n")
            first_group = False


def main():
    root_dir = Path.cwd()
    output_dir = root_dir / "urls"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    clients = ["EdgeGo", "ChromeGo", "FirefoxFQ"]
    all_groups = defaultdict(list)   # 用于最后合并
    
    print("开始执行订阅地址提取任务...\n")
    
    for client in clients:
        groups = process_folder(client, root_dir)
        
        if groups:
            # 生成单个客户端的 sources 文件
            client_file = output_dir / f"{client}_sources.txt"
            write_sources_file(groups, client_file)
            print(f"✅ 已生成 {client_file.name}  ({len(groups)} 个分组)")
            
            # 收集到总分组中（用于最后合并）
            for group_name, urls in groups.items():
                all_groups[group_name].extend(urls)
    
    # ==================== 生成最终合并的 sources.txt ====================
    final_groups = {}
    for group_name, url_list in all_groups.items():
        seen = set()
        unique_urls = []
        for url in url_list:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        if unique_urls:
            final_groups[group_name] = unique_urls
    
    final_file = output_dir / "sources.txt"
    write_sources_file(final_groups, final_file)
    
    # 输出统计信息
    print("\n" + "=" * 70)
    print("🎉 全部处理完成！共生成 4 个文件：")
    print(f"   • {output_dir}/EdgeGo_sources.txt")
    print(f"   • {output_dir}/ChromeGo_sources.txt")
    print(f"   • {output_dir}/FirefoxFQ_sources.txt")
    print(f"   • {output_dir}/sources.txt   ← 最终合并文件")
    print("=" * 70)
    
    total_groups = len(final_groups)
    total_urls = sum(len(urls) for urls in final_groups.values())
    print(f"最终 sources.txt 包含：{total_groups} 个分组，共 {total_urls} 条订阅地址（分组内去重）")


if __name__ == "__main__":
    main()
