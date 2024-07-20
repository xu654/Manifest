import os
import vdf
import winreg
import argparse
import psutil
import requests
import traceback
import subprocess
import colorlog
import logging
import json
import time
import tkinter as tk
import ttkbootstrap as tb
from pathlib import Path
from multiprocessing.pool import ThreadPool
from multiprocessing.dummy import Pool, Lock
from threading import Thread
import re
import urllib3
import pyautogui

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 设置游戏列表文件
GAME_LIST_FILE = 'game_list.json'

def load_game_list():
    if os.path.exists(GAME_LIST_FILE):
        with open(GAME_LIST_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_game_list(game_list):
    with open(GAME_LIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(game_list, f, indent=4)

def init_log(text_widget):
    logger = logging.getLogger('EEUN')
    logger.setLevel(logging.DEBUG)
    stream_handler = ColoredLogger(text_widget)
    stream_handler.setLevel(logging.DEBUG)
    fmt_string = '%(log_color)s[%(name)s][%(levelname)s]%(message)s'
    log_colors = {
        'DEBUG': 'white',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'purple'
    }
    fmt = colorlog.ColoredFormatter(fmt_string, log_colors=log_colors)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)
    return logger

class ColoredLogger(logging.StreamHandler):
    LEVEL_COLORS = {
        logging.DEBUG: 'white',
        logging.INFO: 'green',
        logging.WARNING: 'yellow',
        logging.ERROR: 'red',
        logging.CRITICAL: 'purple',
    }

    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        level_color = self.LEVEL_COLORS.get(record.levelno, 'black')
        self.text_widget.configure(state='normal')
        self.text_widget.tag_configure(record.levelname, foreground=level_color)
        self.text_widget.insert(tk.END, msg + '\n', record.levelname)
        self.text_widget.configure(state='disabled')
        self.text_widget.yview(tk.END)

def load_config():
    default_config = {"Github_Persoal_Token": "", "Custom_Steam_Path": ""}
    if not os.path.exists('./config.json'):
        return default_config
    try:
        with open('./config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
            return config
    except json.JSONDecodeError:
        return default_config

config = load_config()
lock = Lock()

print('\033[1;32;40m  _____   _____    _    _    _   _ \033[0m')
print('\033[1;32;40m | ____| | ____|  | |  | |  | \ | |\033[0m')
print('\033[1;32;40m | |__   | |__    | |  | |  |  \| |\033[0m')
print('\033[1;32;40m |  __|  |  __|   | |  | |  | . ` |\033[0m')
print('\033[1;32;40m | |___  | |___   | |__| |  | |\  |\033[0m')
print('\033[1;32;40m |_____| |_____|   \____/   |_| \_|\033[0m')

def get_steam_path():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam')
        steam_path = Path(winreg.QueryValueEx(key, 'SteamPath')[0])
    except Exception as e:
        steam_path = Path()
    custom_steam_path = config.get("Custom_Steam_Path", "")
    if custom_steam_path:
        return Path(custom_steam_path)
    else:
        return steam_path

steam_path = get_steam_path()
isGreenLuma = any((steam_path / dll).exists() for dll in ['GreenLuma_2024_x86.dll', 'GreenLuma_2024_x64.dll', 'User32.dll'])

def get(sha, path):
    url_list = [
        f'https://gcore.jsdelivr.net/gh/{repo}@{sha}/{path}',
        f'https://fastly.jsdelivr.net/gh/{repo}@{sha}/{path}',
        f'https://cdn.jsdelivr.net/gh/{repo}@{sha}/{path}',
        f'https://github.moeyy.xyz/https://raw.githubusercontent.com/{repo}/{sha}/{path}',
        f'https://mirror.ghproxy.com/https://raw.githubusercontent.com/{repo}/{sha}/{path}',
        f'https://ghproxy.org/https://raw.githubusercontent.com/{repo}/{sha}/{path}',
        f'https://raw.githubusercontent.com/{repo}/{sha}/{path}'
    ]
    retry = 5
    while retry:
        for url in url_list:
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    return r.content
                else:
                    log.error(f'获取失败: {path} - 状态码: {r.status_code}')
            except requests.exceptions.ConnectionError:
                log.error(f'获取失败: {path} - 连接错误')
        retry -= 1
        log.warning(f'重试剩余次数: {retry} - {path}')
    log.error(f'超过最大重试次数: {path}')
    raise Exception(f'Failed to download: {path}')

def get_manifest(sha, path, steam_path: Path, required_depot_id: str):
    collected_depots = []
    try:
        if path.endswith('.manifest'):
            depot_cache_path = steam_path / 'depotcache'
            with lock:
                if not depot_cache_path.exists():
                    depot_cache_path.mkdir(exist_ok=True)
            save_path = depot_cache_path / path
            if save_path.exists():
                with lock:
                    log.warning(f'已存在清单: {path}')
                return collected_depots
            content = get(sha, path)
            with lock:
                log.info(f'清单下载成功: {path}')
            with save_path.open('wb') as f:
                f.write(content)
            
            # 从文件名中提取 depot_id 和 manifest_id
            file_name = save_path.stem
            try:
                depot_id, manifest_id = file_name.split('_')
                if depot_id == required_depot_id:
                    log.info(f'提取到 depot_id: {depot_id}, manifest_id: {manifest_id}')
                    set_manifest_id(steam_path, depot_id, manifest_id)
                else:
                    log.warning(f'忽略无关的清单文件 {file_name}')
            except ValueError:
                log.error(f'文件名 {file_name} 无法分解为 depot_id 和 manifest_id')
        elif path == 'Key.vdf':
            content = get(sha, path)
            with lock:
                log.info(f'密钥下载成功: {path}')
            depots_config = vdf.loads(content.decode(encoding='utf-8'))
            for depot_id, depot_info in depots_config['depots'].items():
                collected_depots.append((depot_id, depot_info['DecryptionKey']))
    except KeyboardInterrupt:
        raise
    except Exception as e:
        log.error(f'处理失败: {path} - {str(e)}')
        traceback.print_exc()
        raise
    return collected_depots



def depotkey_merge(config_path, depots_config):
    if not config_path.exists():
        with lock:
            log.error('Steam默认配置不存在，可能是没有登录账号')
        return
    with open(config_path, encoding='utf-8') as f:
        config = vdf.load(f)
    software = config['InstallConfigStore']['Software']
    valve = software.get('Valve') or software.get('valve')
    steam = valve.get('Steam') or valve.get('steam')
    if 'depots' not in steam:
        steam['depots'] = {}
    steam['depots'].update(depots_config['depots'])
    with open(config_path, 'w', encoding='utf-8') as f:
        vdf.dump(config, f, pretty=True)
    return True

def greenluma_add(depot_id_list):
    app_list_path = steam_path / 'AppList'
    if app_list_path.is_file():
        app_list_path.unlink(missing_ok=True)
    if not app_list_path.is_dir():
        app_list_path.mkdir(parents=True, exist_ok=True)
    depot_dict = {}
    for i in app_list_path.iterdir():
        if i.stem.isdecimal() and i.suffix == '.txt':
            with i.open('r', encoding='utf-8') as f:
                app_id_ = f.read().strip()
                depot_dict[int(i.stem)] = None
                if app_id_.isdecimal():
                    depot_dict[int(i.stem)] = int(app_id_)
    for depot_id in depot_id_list:
        if int(depot_id) not in depot_dict.values():
            index = max(depot_dict.keys()) + 1 if depot_dict.keys() else 0
            if index != 0:
                for i in range(max(depot_dict.keys())):
                    if i not in depot_dict.keys():
                        index = i
                        break
            with (app_list_path / f'{index}.txt').open('w', encoding='utf-8') as f:
                f.write(str(depot_id))
            depot_dict[index] = int(depot_id)
    return True

def check_github_api_limit(headers):
    url = 'https://api.github.com/rate_limit'
    r = requests.get(url, headers=headers)
    remain_limit = r.json()['rate']['remaining']
    use_limit = r.json()['rate']['used']
    reset_time = r.json()['rate']['reset']
    f_reset_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reset_time))
    log.info(f'已用Github请求数：{use_limit}')
    log.info(f'剩余Github请求数：{remain_limit}')
    if r.status_code == '429':
        log.info(f'你的Github Api请求数已超限，请尝试增加Personal Token')
        log.info(f'请求数重置时间：{f_reset_time}')
    return True

def check_process_running(process_name):
    for process in psutil.process_iter(['name']):
        if process.info['name'] == process_name:
            return True
    return False


def restart_steam(steam_path: Path):
    steam_exe = steam_path / 'Steam.exe'
    dll_injector = steam_path / 'DLLInjector.exe'
    
    if not steam_exe.exists():
        log.error(f'{steam_exe} 不存在，请检查路径和文件是否正确')
        return
    
    try:
        steam_running = any(process.info['name'].lower() == 'steam.exe' for process in psutil.process_iter(['name']))

        if steam_running:
            # 关闭所有运行中的 Steam 进程
            for process in psutil.process_iter(['name']):
                if process.info['name'].lower() == 'steam.exe':
                    process.terminate()
                    process.wait()
            time.sleep(5)  # 确保所有 Steam 进程已经终止
            log.info('Steam 已关闭')

        # 确保 DLLInjector 未运行
        dll_injector_running = any(process.info['name'].lower() == 'dllinjector.exe' for process in psutil.process_iter(['name']))
        if dll_injector_running:
            log.warning('DLLInjector.exe 已经在运行，无法再次启动')
            return

        # 启动 DLLInjector.exe
        subprocess.Popen([dll_injector])
        log.info('DLLInjector.exe 已启动')

    except subprocess.CalledProcessError as e:
        log.error(f'调用 DLLInjector.exe 时发生错误: {e}')
    except Exception as e:
        log.error(f'重启 Steam 过程中出现错误: {str(e)}')
        traceback.print_exc()

def ensure_steam_is_running(steam_path: Path):
    steam_exe = steam_path / 'Steam.exe'

    if not steam_exe.exists():
        log.error(f'{steam_exe} 不存在，请检查路径和文件是否正确')
        return

    steam_running = any(process.info['name'].lower() == 'steam.exe' for process in psutil.process_iter(['name']))
    
    if not steam_running:
        try:
            subprocess.Popen([steam_exe])
            log.info('Steam 已启动')
        except subprocess.CalledProcessError as e:
            log.error(f'启动 Steam 时发生错误: {e}')
        except Exception as e:
            log.error(f'启动 Steam 过程中出现错误: {str(e)}')
            traceback.print_exc()
def set_manifest_id(steam_path: Path, depot_id: str, manifest_id: str):
    config_path = steam_path / 'config' / 'config.vdf'
    
    if not config_path.exists():
        log.error(f'{config_path} 不存在，请检查路径和文件是否正确')
        return
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = vdf.load(f)
    
    install_config = config.get('InstallConfigStore', {})
    software = install_config.get('Software', {})
    valve = software.get('Valve', {})
    steam = valve.get('Steam', {})
    
    if 'Manifests' not in steam:
        steam['Manifests'] = {}
    
    steam['Manifests'][depot_id] = manifest_id
    log.info(f'Set manifest ID for {depot_id} to {manifest_id}')
    
    with open(config_path, 'w', encoding='utf-8') as f:
        vdf.dump(config, f, pretty=True)
    log.info(f'{config_path} 写入成功')
def main(app_id, required_depot_id):
    app_id_list = list(filter(str.isdecimal, app_id.strip().split('-')))
    app_id = app_id_list[0]
    github_token = config.get("Github_Persoal_Token", "")
    headers = {'Authorization': f'Bearer {github_token}'} if github_token else None
    if headers:
        check_github_api_limit(headers)
    url = f'https://api.github.com/repos/{repo}/branches/{app_id}'
    r = requests.get(url, headers=headers)
    if 'commit' in r.json():
        sha = r.json()['commit']['sha']
        url = r.json()['commit']['commit']['tree']['url']
        date = r.json()['commit']['commit']['author']['date']
        r = requests.get(url, headers=headers, verify=False)
        if 'tree' in r.json():
            result_list = []
            collected_depots = []
            with Pool(32) as pool:
                pool: ThreadPool
                for i in r.json()['tree']:
                    result_list.append(pool.apply_async(get_manifest, (sha, i['path'], steam_path, required_depot_id)))
                try:
                    for result in result_list:
                        collected_depots.extend(result.get())
                except KeyboardInterrupt:
                    with lock:
                        pool.terminate()
                    raise
            if collected_depots:
                if isGreenLuma:
                    greenluma_add([app_id])
                    depot_config = {'depots': {depot_id: {'DecryptionKey': depot_key} for depot_id, depot_key in collected_depots}}
                    depotkey_merge(steam_path / 'config' / 'config.vdf', depot_config)
                    if greenluma_add([int(i) for i in depot_config['depots'] if i.isdecimal()]):
                        log.info('找到GreenLuma，已添加解锁文件')
                depot_cache_path = steam_path / 'depotcache'
                # 从下载的清单文件中提取 depot_id 和 manifest_id 并设置
                for depot_id, manifest_id in [file.stem.split('_') for file in depot_cache_path.glob('*.manifest')]:
                    if depot_id == required_depot_id:
                        log.info(f'设置清单 {depot_id} 为 {manifest_id}')
                        set_manifest_id(steam_path, depot_id, manifest_id)
                restart_steam(steam_path)  # 重启 Steam
                log.info(f'清单最后更新时间：{date}')
                log.info(f'入库成功: {app_id}')
                return True
    log.error(f'清单下载或生成失败: {app_id}，请检查是否存在该游戏')
    return False



parser = argparse.ArgumentParser()
parser.add_argument('-a', '--app-id')
args = parser.parse_args()
repo = 'xu654/Manifest'



def start_process():
    app_id = app_id_entry.get()
    required_depot_id = depot_id_entry.get()  # 假设有一个输入框用于获取 depot_id
    if app_id and required_depot_id:
        thread = Thread(target=run_main, args=(app_id, required_depot_id))
        thread.start()


def add_game_to_list(app_id):
    if app_id not in game_list:
        game_list.append(app_id)
        save_game_list(game_list)
        create_game_list(game_list_frame)  # Update the GUI list

def start_process():
    app_id = app_id_entry.get()
    if app_id:
        add_game_to_list(app_id)  # Add the app_id to the list
        thread = Thread(target=run_main, args=(app_id,))
        thread.start()

def open_url(url):
    subprocess.Popen(['start', url], shell=True)

def delete_game(app_id):
    if app_id in game_list:
        game_list.remove(app_id)
        save_game_list(game_list)
        create_game_list(game_list_frame)  # Update the GUI list

def create_game_list(frame, search_text=""):
    for widget in frame.winfo_children():
        widget.destroy()

    for app_id in game_list:
        if search_text.lower() in app_id.lower():
            row = tk.Frame(frame)
            row.pack(fill=tk.X)

            label = tk.Label(row, text=app_id)
            label.pack(side=tk.LEFT, padx=5, pady=5)

            install_button = tb.Button(row, text="安装游戏", command=lambda app_id=app_id: install_game(app_id))
            install_button.pack(side=tk.LEFT, padx=5, pady=5)

            delete_button = tb.Button(row, text="删除", command=lambda app_id=app_id: delete_game(app_id), bootstyle="danger")
            delete_button.pack(side=tk.LEFT, padx=5, pady=5)

def install_game(app_id):
    subprocess.Popen(f'start steam://install/{app_id}', shell=True)

def create_gui():
    root = tb.Window(themename="litera")
    root.title("EEUNGLv1.0")
    root.geometry("1100x600")

    frame = tb.Frame(root)
    frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    app_id_label = tb.Label(frame, text="需要入库的App ID:")
    app_id_label.grid(row=0, column=0, sticky='w')

    global app_id_entry
    app_id_entry = tb.Entry(frame)
    app_id_entry.grid(row=1, column=0, sticky='ew', padx=(0, 10))

    right_search_label = tb.Label(frame, text="已入库的appid")
    right_search_label.grid(row=0, column=1, sticky='w')

    global search_entry
    search_entry = tb.Entry(frame)
    search_entry.grid(row=1, column=1, sticky='ew', padx=(10, 0))

    frame.grid_columnconfigure(0, weight=1)
    frame.grid_columnconfigure(1, weight=1)

    left_button_frame = tb.Frame(frame)
    left_button_frame.grid(row=2, column=0, pady=5, sticky='ew')

    right_button_frame = tb.Frame(frame)
    right_button_frame.grid(row=2, column=1, pady=5, sticky='ew')

    start_button = tb.Button(left_button_frame, text="开始入库", command=start_process)
    start_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

    custom_button_1 = tb.Button(left_button_frame, text="游戏Appid查询", command=lambda: open_url("https://steamui.com/"))
    custom_button_1.pack(side=tk.LEFT, expand=True, fill=tk.X)

    custom_button_2 = tb.Button(left_button_frame, text="解决网络报错", command=lambda: open_url("https://www.kdocs.cn/l/cnrZ8Jse8ws2"))
    custom_button_2.pack(side=tk.LEFT, expand=True, fill=tk.X)

    custom_button_3 = tb.Button(left_button_frame, text="图文教程（必看）", command=lambda: open_url("https://kdocs.cn/l/ccLSaRuZU7xZ"))
    custom_button_3.pack(side=tk.LEFT, expand=True, fill=tk.X)

    refresh_button = tb.Button(right_button_frame, text="游戏修改器", command=lambda: open_url("https://kdocs.cn/l/cdLJGOjQKncP"))
    refresh_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

    restart_button = tb.Button(right_button_frame, text="重启Steam", command=restart_steam)
    restart_button.pack(side=tk.LEFT, expand=True, fill=tk.X)

    # 创建一个新的框架来包含日志文本框和右侧滚动区域
    content_frame = tb.Frame(frame)
    content_frame.grid(row=3, column=0, columnspan=2, sticky='nsew')

    frame.grid_rowconfigure(3, weight=1)
    content_frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_columnconfigure(1, weight=1)
    content_frame.grid_rowconfigure(0, weight=1)

    log_text = tk.Text(content_frame, wrap=tk.WORD, state='disabled', height=10)
    log_text.grid(row=0, column=0, sticky='nsew', padx=(0, 10), pady=(5, 0))

    # 初始化日志
    global log
    log = init_log(log_text)
    log.propagate = False

    initial_message_lines = [
        "  _____   _____   _   _   _   _  ", 
        " | ____| | ____| | | | | | \\ | | ", 
        " | |__   | |__   | | | | |  \\| | ", 
        " |  __|  |  __|  | | | | | . ` | ", 
        " | |___  | |___  | |_| | | |\\  | ", 
        " |_____| |_____|  \\___/  |_| \\_| ",
        "\n",
        "欢迎使用EEUN"
        "\n",
        "点击“游戏Appid查询”，搜索需要的游戏名字，点击游戏的右上方数字就会自动复制，快捷键Ctrl+v即可粘贴到EEUN上方的文本框，之后点击“开始入库”即可，入库完成后点击重启steam，只能点击右侧的重启steam，不要手动重启"
        "\n",
        "右侧的商店网址需要加速steam才可以进入"
    ]

    log_text.configure(state='normal')
    log_text.tag_configure('header', foreground='blue', font=('Courier', 12, 'bold'))
    for line in initial_message_lines:
        log_text.insert(tk.END, line + '\n', 'header')
    log_text.configure(state='disabled')
    log_text.yview(tk.END)

    right_frame = tb.Frame(content_frame)
    right_frame.grid(row=0, column=1, sticky='nsew', padx=(10, 0), pady=(5, 0))

    # 滚动区域
    canvas = tk.Canvas(right_frame)
    scrollbar = tb.Scrollbar(right_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tb.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    global game_list_frame
    game_list_frame = scrollable_frame

    # 添加鼠标滚轮支持
    def on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    canvas.bind_all("<MouseWheel>", on_mousewheel)

    global game_list
    game_list = load_game_list()  # Load the game list

    create_game_list(game_list_frame)  # Display the loaded game list

    root.mainloop()

if __name__ == '__main__':
    repo = 'xu654/Manifest'
    create_gui()
