import ctypes
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from datetime import datetime
import win32event
import win32api
import winerror

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.StreamHandler()])

# Проверка на повторный запуск
mutex = win32event.CreateMutex(None, 1, 'TaskManagerMutex')
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    messagebox.showwarning("Предупреждение", "Программа уже запущена!")
    sys.exit(0)

# Определение структур данных для работы с DLL
class ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_ulong),
        ("name", ctypes.c_wchar * 260),
        ("cpuUsage", ctypes.c_double),
        ("memoryUsage", ctypes.c_size_t),  # Working Set
        ("privateBytes", ctypes.c_size_t),  # Private Bytes
        ("pagefileUsage", ctypes.c_size_t),  # Pagefile Usage
        ("readBytes", ctypes.c_ulonglong),  # Total Read Bytes
        ("writeBytes", ctypes.c_ulonglong),  # Total Write Bytes
        ("diskUsage", ctypes.c_double),  # Disk Activity (KB/s)
        ("creationTime", ctypes.c_ulonglong),
        ("exitTime", ctypes.c_ulonglong),
        ("kernelTime", ctypes.c_ulonglong),
        ("userTime", ctypes.c_ulonglong),
        ("priority", ctypes.c_ulong),
        ("threadCount", ctypes.c_ulong)
    ]

class ThreadInfo(ctypes.Structure):
    _fields_ = [
        ("threadId", ctypes.c_ulong),
        ("processId", ctypes.c_ulong),
        ("priority", ctypes.c_ulong),
        ("kernelTime", ctypes.c_ulonglong),
        ("userTime", ctypes.c_ulonglong),
        ("state", ctypes.c_ulong)
    ]

# Константы
MAX_PROCESSES = 4096
MAX_THREADS = 8192
PRIORITY_CLASSES = {
    0x00000040: "Idle",
    0x00004000: "Below Normal",
    0x00000020: "Normal",
    0x00008000: "Above Normal",
    0x00000080: "High",
    0x00000100: "Realtime"
}

def load_process_monitor_dll():
    try:
        possible_paths = [
            os.path.join(os.getcwd(), "ProcessMonitor.dll"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ProcessMonitor.dll"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ProcessMonitor.dll"),
            os.path.join(os.path.expanduser("~"), "Desktop", "ProcessMonitor.dll"),
            os.path.join(os.path.expanduser("~"), "Рабочий стол", "ProcessMonitor.dll"),
            r"C:\Users\studentColl\Desktop\ProcessMonitor.dll",
            r"C:\Users\studentColl\Desktop\cursor\ProcessMonitor.dll"
        ]
        dll_path = None
        for path in possible_paths:
            if os.path.exists(path):
                dll_path = path
                logging.info(f"DLL найдена по пути: {dll_path}")
                break
        if not dll_path:
            from tkinter import filedialog
            messagebox.showinfo("Выбор DLL", "Не удалось автоматически найти ProcessMonitor.dll. Пожалуйста, укажите путь к файлу.")
            dll_path = filedialog.askopenfilename(title="Выберите ProcessMonitor.dll",
                                                  filetypes=[("DLL files", "*.dll")])
            if not dll_path:
                raise FileNotFoundError("Пользователь не выбрал файл DLL")
        pm = ctypes.WinDLL(dll_path)
        logging.info(f"DLL успешно загружена: {dll_path}")
        return pm
    except Exception as e:
        logging.error(f"Не удалось загрузить DLL: {e}")
        messagebox.showerror("Ошибка",
                             f"Не удалось загрузить ProcessMonitor.dll: {e}\n\nУбедитесь, что файл существует и доступен.")
        sys.exit(1)

def setup_admin_check_functions(pm):
    pm.PM_IsAdmin.restype = ctypes.c_bool
    pm.PM_IsAdmin.argtypes = []
    pm.PM_RequestAdminRights.restype = ctypes.c_bool
    pm.PM_RequestAdminRights.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    return pm

# Загружаем DLL для проверки прав администратора
pm_dll = load_process_monitor_dll()
pm_dll = setup_admin_check_functions(pm_dll)

# Проверяем и запрашиваем права администратора при необходимости
if not pm_dll.PM_IsAdmin():
    executable_path = sys.executable
    command_line = " ".join(sys.argv)
    if pm_dll.PM_RequestAdminRights(executable_path, command_line):
        # Выходим из текущего экземпляра программы,
        # так как будет запущен новый экземпляр с правами администратора
        sys.exit(0)
    else:
        messagebox.showerror("Ошибка", "Для работы программы требуются права администратора")
        sys.exit(1)

class ProcessMonitor:
    def __init__(self):
        self._load_dll()
        self._setup_functions()
        self._initialize()

    def _load_dll(self):
        self.pm = pm_dll  # Используем уже загруженную DLL

    def _setup_functions(self):
        self.pm.PM_Initialize.restype = ctypes.c_bool
        self.pm.PM_Initialize.argtypes = []

        self.pm.PM_GetProcesses.restype = None
        self.pm.PM_GetProcesses.argtypes = [
            ctypes.POINTER(ProcessInfo),
            ctypes.POINTER(ctypes.c_int)
        ]

        self.pm.PM_GetThreads.restype = None
        self.pm.PM_GetThreads.argtypes = [
            ctypes.c_ulong,
            ctypes.POINTER(ThreadInfo),
            ctypes.POINTER(ctypes.c_int)
        ]

        self.pm.PM_TerminateProcess.restype = ctypes.c_bool
        self.pm.PM_TerminateProcess.argtypes = [ctypes.c_ulong]

        self.pm.PM_SetProcessPriority.restype = ctypes.c_bool
        self.pm.PM_SetProcessPriority.argtypes = [ctypes.c_ulong, ctypes.c_ulong]

        self.pm.PM_CreateProcess.restype = ctypes.c_bool
        self.pm.PM_CreateProcess.argtypes = [ctypes.c_wchar_p]

        self.pm.PM_GetLastError.restype = ctypes.c_bool
        self.pm.PM_GetLastError.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong)
        ]

        self.pm.PM_Cleanup.restype = None
        self.pm.PM_Cleanup.argtypes = []

    def _initialize(self):
        if not self.pm.PM_Initialize():
            self._show_error("Initialization failed")
            sys.exit(1)

    def _show_error(self, context):
        error_msg = ctypes.create_unicode_buffer(256)
        error_code = ctypes.c_ulong()
        if self.pm.PM_GetLastError(error_msg, ctypes.byref(error_code)):
            msg = f"{context}: {error_msg.value} (code {error_code.value})"
            logging.error(msg)
            messagebox.showerror("Error", msg)
        else:
            logging.error(f"{context}: Unknown error")

    def get_processes(self):
        processes = (ProcessInfo * MAX_PROCESSES)()
        count = ctypes.c_int(0)
        self.pm.PM_GetProcesses(processes, ctypes.byref(count))
        result = []
        for i in range(count.value):
            result.append({
                "pid": processes[i].pid,
                "name": processes[i].name,
                "cpu": processes[i].cpuUsage,
                "memory": processes[i].memoryUsage / (1024 * 1024),  # Working Set in MB
                "private_memory": processes[i].privateBytes / (1024 * 1024),  # Private Bytes in MB
                "pagefile": processes[i].pagefileUsage / (1024 * 1024),  # Pagefile in MB
                "read_bytes": processes[i].readBytes,
                "write_bytes": processes[i].writeBytes,
                "disk": processes[i].diskUsage,  # Already in KB/s from DLL
                "threads": processes[i].threadCount,
                "priority": processes[i].priority,
                "creation_time": processes[i].creationTime,
                "kernel_time": processes[i].kernelTime,
                "user_time": processes[i].userTime
            })
        return result

    def get_threads(self, pid):
        threads = (ThreadInfo * MAX_THREADS)()
        count = ctypes.c_int(0)
        self.pm.PM_GetThreads(pid, threads, ctypes.byref(count))
        result = []
        for i in range(count.value):
            result.append({
                "tid": threads[i].threadId,
                "pid": threads[i].processId,
                "priority": threads[i].priority,
                "state": threads[i].state,
                "kernel_time": threads[i].kernelTime,
                "user_time": threads[i].userTime
            })
        return result

    def terminate_process(self, pid):
        if not self.pm.PM_TerminateProcess(pid):
            self._show_error("Failed to terminate process")
            return False
        return True

    def set_priority(self, pid, priority):
        if not self.pm.PM_SetProcessPriority(pid, priority):
            self._show_error("Failed to set process priority")
            return False
        return True

    def create_process(self, path):
        if not self.pm.PM_CreateProcess(path):
            self._show_error("Failed to create process")
            return False
        return True

    def cleanup(self):
        self.pm.PM_Cleanup()

class ProcessMonitorApp:
    def __init__(self, root):
        self.root = root
        self.monitor = ProcessMonitor()
        self.sort_direction = {}

        # Инициализация истории для графиков
        self.cpu_usage_history = []
        self.memory_usage_history = []
        self.disk_usage_history = []  # Added disk usage history
        self.max_history = 30

        self.setup_ui()
        self.update_process_list()

    def setup_ui(self):
        # Создаем фрейм для поиска и запуска процессов
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        # Фрейм для поиска
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(search_frame, text="Поиск процесса:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Фрейм для запуска процесса
        launch_frame = ttk.Frame(top_frame)
        launch_frame.pack(side=tk.LEFT, fill=tk.X, padx=5)
        ttk.Label(launch_frame, text="Запуск:").pack(side=tk.LEFT, padx=5)
        self.path_entry = ttk.Entry(launch_frame, width=40)
        self.path_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(launch_frame, text="Запустить", command=self.create_process).pack(side=tk.LEFT, padx=5)

        # Кнопки для отображения графиков
        buttons_frame = ttk.Frame(top_frame)
        buttons_frame.pack(side=tk.RIGHT, padx=5)

        ttk.Button(buttons_frame, text="ЦП", command=lambda: self.show_graph("CPU")).pack(side=tk.LEFT, padx=2)
        ttk.Button(buttons_frame, text="Память", command=lambda: self.show_graph("Memory")).pack(side=tk.LEFT, padx=2)
        ttk.Button(buttons_frame, text="Диск", command=lambda: self.show_graph("Disk")).pack(side=tk.LEFT, padx=2)

        # Привязываем событие изменения текста к функции поиска
        self.search_var.trace('w', self.filter_processes)

        # Создаем и настраиваем таблицу процессов
        columns = {
            "pid": "PID",
            "name": "Имя процесса",
            "type": "Тип",
            "cpu": "CPU (%)",
            "memory": "Память (МБ)",
            "disk": "Диск (КБ/с)",
            "threads": "Потоки"
        }
        self.tree = ttk.Treeview(self.root, columns=list(columns.keys()), show='headings')

        # Настраиваем заголовки и привязываем сортировку
        for col, name in columns.items():
            self.tree.heading(col, text=name, command=lambda c=col: self.sort_column(c))
            if col in ["pid", "threads"]:
                self.tree.column(col, width=70, anchor=tk.CENTER)
            elif col in ["cpu", "disk"]:
                self.tree.column(col, width=100, anchor=tk.CENTER)
            elif col == "memory":
                self.tree.column(col, width=120, anchor=tk.CENTER)
            elif col == "type":
                self.tree.column(col, width=150, anchor=tk.CENTER)
            else:
                self.tree.column(col, width=200)

        # Добавляем полосу прокрутки
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Размещаем элементы
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Привязываем контекстное меню к таблице
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Настраиваем автообновление каждые 2 секунды
        self.root.after(2000, self.update_process_list)

    def sort_column(self, column):
        current_state = self.sort_direction.get(column)
        new_state = False if current_state is None else True if current_state is False else None
        self.sort_direction[column] = new_state

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col.split()[0])

        if new_state is None:
            return

        items = [(self.tree.set(k, column), k) for k in self.tree.get_children('')]
        if column == "pid":
            items.sort(key=lambda x: int(x[0]), reverse=not new_state)
        elif column == "cpu":
            items.sort(key=lambda x: float(x[0].replace('%', '')) if x[0] != '0%' else 0.0,
                       reverse=not new_state)
        elif column in ("memory", "disk"):
            items.sort(key=lambda x: float(x[0].split()[0]) if x[0].split()[0] != '0' else 0.0,
                       reverse=not new_state)
        else:
            items.sort(reverse=not new_state)

        for index, (val, k) in enumerate(items):
            self.tree.move(k, '', index)

        direction = "▲" if new_state else "▼"
        self.tree.heading(column, text=f"{column} {direction}")

    def get_process_type(self, process_name, pid):
        system_processes = [
            'System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe', 'winlogon.exe',
            'fontdrvhost.exe', 'spoolsv.exe', 'MsMpEng.exe', 'ctfmon.exe',
            'taskhostw.exe', 'explorer.exe', 'shellexperiencehost.exe',
            'runtimebroker.exe', 'searchui.exe', 'sihost.exe'
        ]

        if pid < 10 or process_name.lower() in [p.lower() for p in system_processes]:
            return "System", "System.Treeview.Row"
        if process_name.endswith('.exe') and not (
            process_name.startswith('svc') or
            'service' in process_name.lower() or
            'daemon' in process_name.lower() or
            'agent' in process_name.lower()
        ):
            return "Application", "App.Treeview.Row"
        return "Background", "Background.Treeview.Row"

    def update_process_list(self):
        try:
            self.root.update_idletasks()

            # Запоминаем текущее положение скрола
            scroll_position = self.tree.yview()

            # Сохраняем ID выбранного элемента
            selected = self.tree.selection()
            selected_pid = None
            if selected:
                try:
                    selected_pid = self.tree.item(selected[0], "values")[0]
                except:
                    pass

            current_sort_column = None
            current_sort_state = None
            for col in self.tree["columns"]:
                heading_text = self.tree.heading(col)["text"]
                if "▲" in heading_text:
                    current_sort_column = col
                    current_sort_state = True
                    break
                elif "▼" in heading_text:
                    current_sort_column = col
                    current_sort_state = False
                    break

            self.tree.delete(*self.tree.get_children())
            processes = self.monitor.get_processes()

            # Обновляем историю использования ресурсов
            total_cpu = sum(proc['cpu'] for proc in processes)
            total_memory = sum(proc['memory'] for proc in processes)
            total_disk = sum(proc['disk'] for proc in processes)

            self.cpu_usage_history.append(total_cpu)
            self.memory_usage_history.append(total_memory)
            self.disk_usage_history.append(total_disk)

            if len(self.cpu_usage_history) > self.max_history:
                self.cpu_usage_history.pop(0)
                self.memory_usage_history.pop(0)
                self.disk_usage_history.pop(0)

            for proc in processes:
                proc_type, proc_style = self.get_process_type(proc["name"], proc["pid"])
                item_id = self.tree.insert("", "end", values=(
                    proc["pid"],
                    proc["name"],
                    proc_type,
                    f"{proc['cpu']:.1f}%" if proc['cpu'] > 0 else "0%",
                    f"{proc['memory']:.1f} МБ",
                    f"{proc['disk']:.2f} КБ/с",
                    proc["threads"]
                ), tags=(proc_style,))
                self.tree.item(item_id, tags=(proc_style,))

            self.tree.tag_configure("System.Treeview.Row", background="#FFE6E6")
            self.tree.tag_configure("Background.Treeview.Row", background="#E6F2FF")
            self.tree.tag_configure("App.Treeview.Row", background="white")

            if current_sort_column and current_sort_state is not None:
                self.sort_direction[current_sort_column] = current_sort_state
                items = [(self.tree.set(k, current_sort_column), k) for k in self.tree.get_children('')]
                if current_sort_column == "pid":
                    items.sort(key=lambda x: int(x[0]), reverse=not current_sort_state)
                elif current_sort_column == "cpu":
                    items.sort(key=lambda x: float(x[0].replace('%', '')) if x[0] != '0%' else 0.0,
                               reverse=not current_sort_state)
                elif current_sort_column in ("memory", "disk"):
                    items.sort(key=lambda x: float(x[0].split()[0]) if x[0].split()[0] != '0' else 0.0,
                               reverse=not current_sort_state)
                else:
                    items.sort(reverse=not current_sort_state)

                for index, (val, k) in enumerate(items):
                    self.tree.move(k, '', index)

                direction = "▲" if current_sort_state else "▼"
                self.tree.heading(current_sort_column, text=f"{current_sort_column} {direction}")

            # Восстанавливаем выделение, если элемент все еще существует
            if selected_pid:
                for child in self.tree.get_children():
                    if self.tree.item(child, "values")[0] == selected_pid:
                        self.tree.selection_set(child)
                        break

            # НЕ используем self.tree.see(child), чтобы не прокручивать к выбранному элементу

            # Восстанавливаем положение скрола
            self.tree.yview_moveto(scroll_position[0])

        except Exception as e:
            logging.error(f"Error updating process list: {e}")
            messagebox.showerror("Ошибка", f"Не удалось обновить список процессов: {e}")

        self.root.after(2000, self.update_process_list)

    def show_graph(self, resource_type):
        # Создаем новое окно для графика
        graph_window = tk.Toplevel(self.root)
        graph_window.title(f"График {resource_type}")
        graph_window.geometry("600x400")

        # Создаем фрейм для графика
        graph_frame = ttk.Frame(graph_window)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Создаем фигуру matplotlib для графика
        fig, ax = plt.subplots(figsize=(5, 3))
        ax.set_xlabel("Время (обновления)")

        # Выбираем данные и настройки для графика
        if resource_type == "CPU":
            title = "Загрузка CPU (%)"
            data = self.cpu_usage_history
            y_label = "CPU (%)"
            y_limit = 100
            color = 'r-'
        elif resource_type == "Memory":
            title = "Использование памяти (МБ)"
            data = self.memory_usage_history
            y_label = "Память (МБ)"
            y_limit = max(self.memory_usage_history) * 1.1 if self.memory_usage_history else 100
            color = 'b-'
        elif resource_type == "Disk":
            title = "Активность диска (КБ/с)"
            data = self.disk_usage_history
            y_label = "Диск (КБ/с)"
            y_limit = max(self.disk_usage_history) * 1.1 if self.disk_usage_history else 100
            color = 'g-'
        else:
            messagebox.showerror("Ошибка", "Неизвестный тип ресурса")
            return

        ax.set_title(title)
        ax.set_ylabel(y_label)
        ax.set_ylim(0, y_limit)
        line, = ax.plot(range(len(data)), data, color)
        ax.set_xlim(0, self.max_history)

        # Встраиваем график в Tkinter
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    def filter_processes(self, *args):
        filter_text = self.search_var.get().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            name = values[1].lower() if len(values) > 1 else ""
            if filter_text in name:
                self.tree.reattach(item, '', 'end')
            else:
                self.tree.detach(item)

    def create_process(self):
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showwarning("Предупреждение", "Введите путь к исполняемому файлу")
            return

        if self.monitor.create_process(path):
            messagebox.showinfo("Успех", f"Процесс {path} успешно запущен")
            self.path_entry.delete(0, tk.END)
            self.update_process_list()
        else:
            messagebox.showerror("Ошибка", f"Не удалось запустить процесс {path}")

    def show_context_menu(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Завершить процесс", command=self.terminate_selected)
        menu.add_command(label="Изменить приоритет", command=self.set_priority_dialog)
        menu.tk_popup(event.x_root, event.y_root)

    def terminate_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Не выбран процесс")
            return

        pid = int(self.tree.item(selected[0], "values")[0])
        name = self.tree.item(selected[0], "values")[1]

        if messagebox.askyesno("Подтверждение", f"Завершить процесс {name} (PID: {pid})?"):
            if self.monitor.terminate_process(pid):
                messagebox.showinfo("Успех", "Процесс успешно завершен")
                self.update_process_list()
            else:
                messagebox.showerror("Ошибка", "Не удалось завершить процесс")

    def set_priority_dialog(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Не выбран процесс")
            return

        pid = int(self.tree.item(selected[0], "values")[0])
        name = self.tree.item(selected[0], "values")[1]

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Приоритет для {name} (PID: {pid})")
        dialog.geometry("300x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Выберите новый приоритет:").pack(pady=10)
        priority_var = tk.IntVar(value=0x00000020)

        for value, text in PRIORITY_CLASSES.items():
            ttk.Radiobutton(dialog,
                            text=text,
                            variable=priority_var,
                            value=value).pack(anchor=tk.W, padx=20, pady=2)

        def apply_priority():
            if self.monitor.set_priority(pid, priority_var.get()):
                messagebox.showinfo("Успех", "Приоритет успешно изменен")
                dialog.destroy()
                self.update_process_list()

        ttk.Button(dialog, text="Применить", command=apply_priority).pack(pady=10)

def main():
    root = tk.Tk()
    root.title("Диспетчер задач")
    root.geometry("1000x600")
    app = ProcessMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
