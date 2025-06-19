import hashlib
import sys
import os
import argparse


def calculate_sha256(file_path):
    """计算文件的 SHA256 哈希值"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # 分块读取文件以避免大文件内存溢出
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"错误：文件 '{file_path}' 不存在")
    except Exception as e:
        raise RuntimeError(f"读取文件时出错: {str(e)}")


def main():
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description="校验文件的 SHA256 哈希值",
        epilog="使用示例：\n"
               "  main.py myfile.zip 9e9aed6c...\n"
               "  main.py -f myfile.zip -H hash.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # 添加参数
    parser.add_argument('file', nargs='?', help='要校验的文件路径')
    parser.add_argument('hash', nargs='?', help='官网提供的 SHA256 哈希值')
    parser.add_argument('-f', '--file', dest='file_path', help='要校验的文件路径')
    parser.add_argument('-H', '--hash', dest='provided_hash', help='官网提供的 SHA256 哈希值或哈希文件路径')
    parser.add_argument('-c', '--case-sensitive', action='store_true', help='启用大小写敏感模式')

    args = parser.parse_args()

    # 处理参数冲突
    file_path = args.file_path or args.file
    provided_hash = args.provided_hash or args.hash

    if not file_path or not provided_hash:
        print("错误：缺少必要参数！")
        parser.print_help()
        sys.exit(1)

    # 如果提供的哈希是文件路径，则读取文件内容
    if os.path.isfile(provided_hash):
        try:
            with open(provided_hash, 'r') as hash_file:
                # 读取哈希值（自动过滤空格和换行）
                provided_hash = hash_file.read().strip()
        except Exception as e:
            print(f"读取哈希文件出错: {str(e)}")
            sys.exit(1)

    # 计算文件哈希
    try:
        calculated_hash = calculate_sha256(file_path)
    except Exception as e:
        print(e)
        sys.exit(1)

    # 比较哈希值
    if args.case_sensitive:
        is_valid = provided_hash == calculated_hash
    else:
        is_valid = provided_hash.lower() == calculated_hash.lower()

    # 打印结果
    print(f"文件路径:\t{os.path.abspath(file_path)}")
    print(f"官方哈希:\t{provided_hash}")
    print(f"计算哈希:\t{calculated_hash}")

    if is_valid:
        print("\n校验结果: ✅ 哈希值匹配！（文件是官方原版）")
    else:
        print("\n校验结果: ❌ 哈希值不匹配！文件可能已被篡改！")
        sys.exit(1)


if __name__ == "__main__":
    main()