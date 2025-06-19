import hashlib
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading


class SHA256CheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("文件校验工具 v1.0")
        self.root.geometry("600x500")
        self.root.resizable(True, True)

        # 应用图标
        try:
            self.root.iconbitmap("icon.ico")  # 确保有图标文件
        except:
            pass

        self.setup_ui()
        self.setup_menu()

    def setup_menu(self):
        # 创建菜单栏
        menubar = tk.Menu(self.root)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="打开文件", command=self.browse_file)
        file_menu.add_command(label="打开哈希文件", command=self.browse_hash_file)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menubar.add_cascade(label="文件", menu=file_menu)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="使用说明", command=self.show_help)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)

    def setup_ui(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))

        self.file_path = tk.StringVar()
        ttk.Label(file_frame, text="目标文件:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=50)
        file_entry.grid(row=0, column=1, padx=(0, 5), sticky=tk.EW)

        browse_btn = ttk.Button(file_frame, text="浏览...", command=self.browse_file)
        browse_btn.grid(row=0, column=2)

        # 哈希值区域
        hash_frame = ttk.LabelFrame(main_frame, text="验证哈希值", padding="10")
        hash_frame.pack(fill=tk.X, pady=(0, 10))

        self.hash_value = tk.StringVar()
        ttk.Label(hash_frame, text="预期哈希值:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        hash_entry = ttk.Entry(hash_frame, textvariable=self.hash_value, width=60)
        hash_entry.grid(row=0, column=1, sticky=tk.EW)

        hash_browse_btn = ttk.Button(hash_frame, text="从文件导入", command=self.browse_hash_file)
        hash_browse_btn.grid(row=0, column=2, padx=(5, 0))

        # 选项区域
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        self.case_sensitive = tk.BooleanVar(value=False)
        case_check = ttk.Checkbutton(options_frame, text="区分大小写", variable=self.case_sensitive)
        case_check.pack(side=tk.LEFT, padx=(0, 10))

        # 进度条
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(0, 10))

        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.check_btn = ttk.Button(button_frame, text="开始校验", command=self.start_check, state=tk.NORMAL)
        self.check_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.copy_btn = ttk.Button(button_frame, text="复制结果", command=self.copy_result, state=tk.DISABLED)
        self.copy_btn.pack(side=tk.LEFT)

        # 结果输出区域
        result_frame = ttk.LabelFrame(main_frame, text="校验结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = scrolledtext.ScrolledText(result_frame, height=8, state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 配置网格权重
        hash_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="选择要校验的文件",
            filetypes=[("所有文件", "*.*")]
        )
        if file_path:
            self.file_path.set(file_path)
            self.status_var.set(f"已选择文件: {os.path.basename(file_path)}")

    def browse_hash_file(self):
        file_path = filedialog.askopenfilename(
            title="选择哈希文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    # 尝试解析常见哈希文件格式
                    content = f.read().strip()
                    if content:
                        # 提取可能的哈希值 (假设是64字符的SHA256)
                        possible_hashes = [word for word in content.split() if
                                           len(word) == 64 and all(c in "0123456789abcdefABCDEF" for c in word)]

                        if possible_hashes:
                            self.hash_value.set(possible_hashes[0])
                            self.status_var.set(f"从文件导入哈希值: {os.path.basename(file_path)}")
                        else:
                            messagebox.showwarning("警告", "文件中未找到有效的SHA256哈希值")
            except Exception as e:
                messagebox.showerror("错误", f"读取文件时出错: {str(e)}")

    def calculate_sha256(self):
        """计算文件的SHA256哈希值，带进度更新"""
        file_path = self.file_path.get()
        if not file_path:
            messagebox.showwarning("警告", "请先选择要校验的文件")
            return None

        if not os.path.exists(file_path):
            messagebox.showerror("错误", f"文件不存在: {file_path}")
            return None

        self.status_var.set("正在计算文件哈希值...")
        self.check_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.root.update()

        try:
            sha256_hash = hashlib.sha256()
            file_size = os.path.getsize(file_path)
            processed = 0

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024 * 10)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    processed += len(chunk)

                    # 更新进度
                    progress_percent = (processed / file_size) * 100
                    self.progress["value"] = progress_percent
                    self.root.update()

            return sha256_hash.hexdigest()
        except Exception as e:
            messagebox.showerror("错误", f"计算哈希时出错: {str(e)}")
            return None
        finally:
            self.progress["value"] = 0
            self.status_var.set("计算完成")
            self.check_btn.config(state=tk.NORMAL)

    def start_check(self):
        """开始校验过程"""
        expected_hash = self.hash_value.get().strip()
        if not expected_hash:
            messagebox.showwarning("警告", "请输入预期的SHA256哈希值")
            return

        # 在新线程中进行计算，避免UI卡顿
        threading.Thread(target=self.perform_check, daemon=True).start()

    def perform_check(self):
        """执行实际的哈希校验"""
        # 获取预期的哈希值
        expected_hash = self.hash_value.get().strip()
        if not expected_hash:
            # 虽然start_check检查过，但以防万一
            messagebox.showwarning("警告", "预期的SHA256哈希值不能为空")
            return

        # 计算文件哈希
        actual_hash = self.calculate_sha256()

        if actual_hash is None:
            return

        # 准备结果展示
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        file_path = self.file_path.get()
        filename = os.path.basename(file_path)

        # 比较哈希值
        is_case_sensitive = self.case_sensitive.get()
        if is_case_sensitive:
            is_valid = expected_hash == actual_hash
        else:
            is_valid = expected_hash.lower() == actual_hash.lower()

        # 构建结果信息
        result_text = f"文件: {filename}\n"
        result_text += f"文件路径: {file_path}\n"
        result_text += f"文件大小: {self.format_size(os.path.getsize(file_path))}\n\n"

        result_text += f"预期哈希: {expected_hash}\n"
        result_text += f"实际哈希: {actual_hash}\n\n"

        # 高亮显示差异部分（如果需要）
        if not is_valid:
            diff_positions = [i for i, (e, a) in enumerate(zip(expected_hash, actual_hash)) if e.lower() != a.lower()]

            if diff_positions:
                result_text += "差异位置: "
                for i in diff_positions:
                    result_text += f"{i + 1} "

        # 添加最终结果
        result_text += "\n\n校验结果: "
        if is_valid:
            result_text += "✅ 匹配！文件完好无损。"
            color = "green"
        else:
            result_text += "❌ 不匹配！文件可能被篡改或损坏。"
            color = "red"

        self.result_text.insert(tk.END, result_text)

        # 高亮显示最终结果
        self.result_text.tag_configure("result", foreground=color, font=("TkDefaultFont", 10, "bold"))
        self.result_text.tag_add("result", f"{result_text.count('\n') + 1}.0", tk.END)

        self.result_text.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.NORMAL)

        # 显示通知
        if is_valid:
            self.status_var.set("校验成功：哈希值匹配！")
        else:
            self.status_var.set("警告：哈希值不匹配！")
            messagebox.showwarning("校验失败", "文件哈希值不匹配，文件可能已被篡改或损坏！")

    def copy_result(self):
        """复制结果到剪贴板"""
        self.result_text.config(state=tk.NORMAL)
        content = self.result_text.get(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_var.set("结果已复制到剪贴板")

    def show_about(self):
        """显示关于对话框"""
        about_text = (
            "文件校验工具 v1.0\n\n"
            "用于验证文件的SHA256哈希值，确保文件完整性。\n\n"
            "功能：\n"
            "- 文件哈希计算\n"
            "- 哈希值比较\n"
            "- 大文件支持\n"
            "- 进度显示\n\n"
            "作者：Drtxdt\n"
            "发布日期：2025-06-19"
        )
        messagebox.showinfo("关于", about_text)

    def show_help(self):
        """显示帮助信息"""
        help_text = (
            "使用说明:\n\n"
            "1. 点击【浏览...】选择要校验的文件\n"
            "2. 在【预期哈希值】框中输入官网提供的SHA256哈希值\n"
            "   - 或使用【从文件导入】按钮从文本文件导入哈希值\n"
            "3. 如需区分大小写，请勾选【区分大小写】选项\n"
            "4. 点击【开始校验】按钮开始计算文件哈希\n"
            "5. 校验结果将显示在下方文本框中\n"
            "6. 校验完成后可以使用【复制结果】按钮复制全部信息\n\n"
            "注意：\n"
            "- 对于大型文件，计算可能需要一些时间\n"
            "- 进度条会显示当前计算进度"
        )

        # 创建帮助窗口
        help_win = tk.Toplevel(self.root)
        help_win.title("使用帮助")
        help_win.geometry("500x400")
        help_win.resizable(True, True)

        text = scrolledtext.ScrolledText(help_win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state=tk.DISABLED)

        ttk.Button(help_win, text="关闭", command=help_win.destroy).pack(pady=10)

    @staticmethod
    def format_size(size_bytes):
        """将文件大小转换为易读的格式"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


if __name__ == "__main__":
    root = tk.Tk()
    app = SHA256CheckerGUI(root)
    root.mainloop()