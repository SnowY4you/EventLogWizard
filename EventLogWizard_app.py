import win32evtlog
import win32evtlogutil
import win32security
import tkinter as tk
import pywintypes
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext
from tkinter import PhotoImage
from tkcalendar import DateEntry
import datetime
import threading

## Create the definition for Search filters
def on_search():
    global log_name, source_name, event_type, event_category, max_events, keywords, start_date, end_date, event_levels, remote_machine, selection, output_text

    try:
        server = remote_machine.get() if selection.get() == "remote" and remote_machine.get() else 'localhost'

        if selection.get() == "remote":
            domain = domain_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            # Use the credentials to log on
            try:
                win32security.LogonUser(
                    username,
                    domain,
                    password,
                    win32security.LOGON32_LOGON_INTERACTIVE,
                    win32security.LOGON32_PROVIDER_DEFAULT
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to log on to remote machine: {e}")
                return

        # Get the selected date and time
        start_date_value = start_date.get_date().strftime("%Y-%m-%d")
        start_hour_value = start_hour.get()
        start_minute_value = start_minute.get()
        start_time = f"{start_date_value} {start_hour_value}:{start_minute_value}:00"
        sd = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")

        end_date_value = end_date.get_date().strftime("%Y-%m-%d")
        end_hour_value = end_hour.get()
        end_minute_value = end_minute.get()
        end_time = f"{end_date_value} {end_hour_value}:{end_minute_value}:00"
        ed = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

        max_events_val = int(max_events.get()) if max_events.get() else None
        levels = [i for level, var in event_levels if var.get() for i in range(1, 6)]

        logs = get_filtered_logs(server, log_name.get(), event_type.get(), event_category.get(), source_name.get(), keywords.get(), sd, ed, max_events_val, levels)

        output_text.delete(1.0, tk.END)
        output_text.tag_configure("yellow_bg", background="#C3C30D")
        output_text.tag_configure("blue_bg", background="#109BAB")

        output_text.insert(tk.END, f"Total records: {len(logs)}\n\n")

        loging_event_ids = {4727, 4728, 4729, 4730, 4720, 4723, 4724, 4725, 4738, 4767, 4722, 4726, 4740, 4781, 4768,
                            4771, 4820, 4647, 4624, 4625, 4648, 4778, 4779, 4800, 4801, 4802, 4803}
        application_hanging_event_ids = {1000, 1001, 1002}

        logon_failure_codes = {
            "0xC0000064": "user name does not exist",
            "0xC000006A": "user name is correct but the password is wrong",
            "0xC0000234": "user is currently locked out",
            "0xC0000072": "account is currently disabled",
            "0xC000006D": "reason not specified (Sub status may provide more information)",
            "0xC000006F": "user tried to logon outside his day of week or time of day restrictions",
            "0xC0000070": "workstation restriction",
            "0xC0000193": "account expiration",
            "0xC0000071": "expired password",
            "0xC0000133": "clocks between DC and other computer too far out of sync",
            "0xC0000224": "user is required to change password at next logon",
            "0xC0000225": "evidently a bug in Windows and not a risk"
        }

        kerberos_failure_codes = {
            "0x6": "Bad user name",
            "0x7": "New computer account?",
            "0x9": "Administrator should reset password",
            "0xC": "Workstation restriction",
            "0x12": "Account disabled, expired, locked out, logon hours restriction",
            "0x17": "The user’s password has expired",
            "0x18": "Bad password",
            "0x20": "Frequently logged by computer accounts",
            "0x25": "Workstation’s clock too far out of sync with the DC’s"
        }

        for log in logs:
            log_details = format_log_details(log, logon_failure_codes, kerberos_failure_codes, loging_event_ids, application_hanging_event_ids)
            output_text.insert(tk.END, log_details + "\n")

            # Apply yellow background to Logged: {log['Time Generated']}
            start_idx = output_text.search("Logged:", "1.0", tk.END)
            if start_idx:
                end_idx = f"{start_idx.split('.')[0]}.end"
                output_text.tag_add("yellow_bg", start_idx, end_idx)

            # Apply Blue background to divider
            start_idx = output_text.search("####################################################################################", "1.0", tk.END)
            if start_idx:
                end_idx = f"{start_idx.split('.')[0]}.end"
                output_text.tag_add("blue_bg", start_idx, end_idx)

    except ValueError as e:
        messagebox.showerror("Error", f"Invalid date format: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def format_log_details(log, logon_failure_codes, kerberos_failure_codes, loging_event_ids, application_hanging_event_ids):
    event_id = log['Event ID']
    if event_id in loging_event_ids:
        log_details = f"""
Logged: {log['Time Generated']}
    Log Name: {log['Log Name']}
    Source: {log['Source Name']}
    Event ID: {log['Event ID']}
    Task Category: {log.get('Event Category', 'N/A')}
    Level: {log.get('Event Type', 'N/A')}
    Keywords: {log.get('Keywords', 'N/A')}
    User: {log.get('Security UserID', 'N/A')}
    Computer: {log.get('Source Name', 'N/A')}
    Description: {log.get('Event Data', 'N/A')}
    Logon Failure Codes:
"""
        for code, description in logon_failure_codes.items():
            log_details += f"    {code} = {description}\n"

        log_details += "Kerberos Failure Codes:\n"
        for code, description in kerberos_failure_codes.items():
            log_details += f"    {code} = {description}\n"

        log_details += f"""
    Logon Info:
        Logon Type: {log.get('Logon Type', 'N/A')}
        Logon ID: {log.get('Logon ID', 'N/A')}
        Logon GUID: {log.get('Logon GUID', 'N/A')}
        Security ID: {log.get('Security ID', 'N/A')}
        Account Domain: {log.get('Account Domain', 'N/A')}
        Account Name: {log.get('Account Name', 'N/A')}
        Virtual Account: {log.get('Virtual Account', 'N/A')}

    Authentication Info:
        Virtual Account: {log.get('Virtual Account', 'N/A')}
        Process ID: {log.get('Process ID', 'N/A')}
        Logon Process: {log.get('Logon Process', 'N/A')}
        Workstation Name: {log.get('Workstation Name', 'N/A')}
        Source Network Address: {log.get('Source Network Address', 'N/A')}
        Source Port: {log.get('Source Port', 'N/A')}
####################################################################################
        """
    elif event_id in application_hanging_event_ids:
        log_details = f"""
Time Generated: {log['Time Generated']}
    Provider Name: {log.get('Provider Name', 'N/A')}
    Event ID: {log['Event ID']}
    Level: {log.get('Event Type', 'N/A')}
    Keywords: {log.get('Keywords', 'N/A')}
    Guid: {log.get('Guid', 'N/A')}
    ResultCode: {log.get('ResultCode', 'N/A')}

    EventData:
        AppName: {log.get('AppName', 'N/A')}
        AppVersion: {log.get('AppVersion', 'N/A')}
        ProcessId: {log.get('Execution ProcessID', 'N/A')}
        ExeFileName: {log.get('ExeFileName', 'N/A')}
        HangType: {log.get('HangType', 'N/A')}
        Component: {log.get('Component', 'N/A')}
        Operation: {log.get('Operation', 'N/A')}
        EventName: {log.get('EventName', 'N/A')}
        Response: {log.get('Response', 'N/A')}
        Channel: {log.get('Channel', 'N/A')}
        Computer: {log.get('Source Name', 'N/A')}
        UserID: {log.get('Security UserID', 'N/A')}
####################################################################################
        """
    else:
        log_details = f"""
Time Generated: {log['Time Generated']}
    Log Name: {log['Log Name']}
    Event ID: {log['Event ID']}
    Logon ID: {log.get('Logon ID', 'N/A')}
    Provider ID: {log.get('Provider ID', 'N/A')}
    Source Name: {log['Source Name']}
    Level: {log.get('Event Type', 'N/A')}
    Event Type: {log['Event Type']}
    Guid: {log.get('Guid', 'N/A')}

    Event Data:
        SubjectUserID: {log.get('Subject UserID', 'N/A')}
        SubjectUserName: {log.get('SubjectUserName', 'N/A')}
        SubjectDomainName: {log.get('SubjectDomainName', 'N/A')}
        SubjectGuid: {log.get('SubjectGuid', 'N/A')}
        SubjectLogonID: {log.get('SubjectLogonID', 'N/A')}

    System:
        Process ID: {log.get('Process ID', 'N/A')}
        Account Name: {log.get('Account Name', 'N/A')}
        Account Domain: {log.get('Account Domain', 'N/A')}
        Computer: {log.get('Computer', 'N/A')}
        Security ID: {log.get('Security ID', 'N/A')}
        Event Category: {log['Event Category']}
        Provider ID: {log.get('Provider ID', 'N/A')}
        Operation: {log.get('Operation', 'N/A')}
        Return Code: {log.get('Return Code', 'N/A')}
####################################################################################
        """
    return log_details

def start_search():
    search_thread = threading.Thread(target=on_search)
    search_thread.start()

    # Create the definition for GUI Style and Structure


def create_gui():
    global log_name, source_name, event_type, event_category, event_id, max_events, keywords, start_date, end_date, event_levels, remote_machine, selection, output_text, domain_entry, username_entry, password_entry, start_hour, start_minute, end_hour, end_minute

    root = tk.Tk()
    root.title("EventLogWizard - Advanced Windows Event Log Viewer")
    root.geometry("1600x900")

    menubar = tk.Menu(root)
    root.config(menu=menubar)

    # Menu with About Information
    def show_about():
        messagebox.showinfo("About EventLogWizard",
                            "EventLogWizard - Advanced Windows Event Log Viewer\nVersion 1.0\nDeveloped by Sandra van Buggenum\nwww.svanbuggenumanalytics.com")

    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)

    # Style settings for Buttons, Frame, Labels, Borders, Icon and Image
    style = ttk.Style()
    style.configure('TButton', background='#AE11AF', foreground='#0E97B6', font=('Verdana', 10))
    style.map('TButton', background=[('active', '#F8F2F5')])

    title_frame = tk.Frame(root, bg="#0E97B6")
    title_frame.pack(padx=10, pady=10, fill=tk.X)

    title_label = tk.Label(title_frame, text="EventLogWizard", font=("Verdana", 16, "bold"), bg="#0E97B6")
    title_label.pack(side=tk.TOP, anchor="center")

    icon_image = tk.PhotoImage(
        file="C:\\Users\\svanb\\OneDrive\\Python\\Automation\\event_log_wizard\\EventLogWizard_logo.png")
    icon_image = icon_image.subsample(10, 10)
    root.icon_image = icon_image

    shadow_frame = tk.Frame(title_frame, bg="#0E97B6", padx=4, pady=4)
    shadow_frame.pack(side=tk.RIGHT, anchor="center", padx=10, pady=10)

    border_frame = tk.Frame(shadow_frame, bg="#B407B1", padx=6, pady=6)
    border_frame.pack()

    image_label = tk.Label(border_frame, image=icon_image, bg="#0E97B6")
    image_label.pack()

    info_label = tk.Label(title_frame,
                          text="Advanced Windows Event Log Viewer to monitor and troubleshoot your system logs with ease.\n\n\nBelieve you can and you're halfway there. - 'Theodore Roosevelt'",
                          font=("Verdana", 10), fg="white", wraplength=800, justify="center", bg="#0E97B6", anchor="w")
    info_label.pack(side=tk.TOP, anchor="center")

    remote_frame = tk.Frame(root)
    remote_frame.pack(padx=10, pady=10, fill=tk.X, anchor='e')

    # Local or Remote Style
    tk.Label(remote_frame, text="Retrieve logs from:").pack(side=tk.LEFT, padx=5)
    selection = tk.StringVar(value="local")
    local_rb = tk.Radiobutton(remote_frame, text="Local", variable=selection, value="local",
                              command=lambda: toggle_remote("local"))
    local_rb.pack(side=tk.LEFT, padx=5)
    remote_rb = tk.Radiobutton(remote_frame, text="Remote", variable=selection, value="remote",
                               command=lambda: toggle_remote("remote"))
    remote_rb.pack(side=tk.LEFT, padx=5)

    remote_machine = tk.Entry(remote_frame, state=tk.DISABLED)
    remote_machine.pack(side=tk.LEFT, padx=5)

    tk.Label(remote_frame, text="Domain:").pack(side=tk.LEFT, padx=5)
    domain_entry = tk.Entry(remote_frame, state=tk.DISABLED)
    domain_entry.pack(side=tk.LEFT, padx=5)

    tk.Label(remote_frame, text="Username:").pack(side=tk.LEFT, padx=5)
    username_entry = tk.Entry(remote_frame, state=tk.DISABLED)
    username_entry.pack(side=tk.LEFT, padx=5)

    tk.Label(remote_frame, text="Password:").pack(side=tk.LEFT, padx=5)
    password_entry = tk.Entry(remote_frame, show="*", state=tk.DISABLED)
    password_entry.pack(side=tk.LEFT, padx=5)

    border_effects = {"raised": tk.RAISED}
    border_frame = tk.Frame(root, bg="#08646C", padx=1, pady=1, relief=border_effects["raised"])
    border_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    frame = tk.Frame(border_frame, bg="#C4EFFE")
    frame.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)

    # Grid Text and Structure
    tk.Label(frame, text="Log Name Keywords:").grid(row=0, column=0, sticky=tk.W)
    log_name = tk.Entry(frame)
    log_name.grid(row=0, column=1, pady=5, sticky=tk.EW)

    tk.Label(frame, text="Source Keywords:").grid(row=1, column=0, sticky=tk.W)
    source_name = tk.Entry(frame)
    source_name.grid(row=1, column=1, pady=5, sticky=tk.EW)

    tk.Label(frame, text="Event Type:").grid(row=2, column=0, sticky=tk.W)
    event_type = tk.Entry(frame)
    event_type.grid(row=2, column=1, pady=5, sticky=tk.EW)

    tk.Label(frame, text="Event Category:").grid(row=3, column=0, sticky=tk.W)
    event_category = tk.Entry(frame)
    event_category.grid(row=3, column=1, pady=5, sticky=tk.EW)

    tk.Label(frame, text="Event ID:").grid(row=4, column=0, sticky=tk.W)
    event_id = tk.Entry(frame, width=26)
    event_id.grid(row=4, column=1, pady=5, sticky=tk.W)

    tk.Label(frame, text="Max Events:").grid(row=5, column=0, sticky=tk.W)
    max_events = tk.Entry(frame, width=26)
    max_events.grid(row=5, column=1, pady=5, sticky=tk.W)

    tk.Label(frame, text="Keywords (, separated):").grid(row=6, column=0, sticky=tk.W)
    keywords = tk.Entry(frame)
    keywords.grid(row=6, column=1, pady=5, sticky=tk.EW)

    # Date and Time Picker
    tk.Label(frame, text="From Date:").grid(row=7, column=0, sticky=tk.W)
    start_date = DateEntry(frame, width=26, background='#109BAB', foreground='white', borderwidth=2)
    start_date.grid(row=7, column=1, pady=5, sticky=tk.W)

    tk.Label(frame, text="From Time:").grid(row=7, column=2, sticky=tk.W)
    start_hour = ttk.Combobox(frame, values=[f"{i:02}" for i in range(24)], width=3)
    start_hour.grid(row=7, column=3, sticky=tk.W, padx=(0, 5))

    start_minute = ttk.Combobox(frame, values=[f"{i:02}" for i in range(0, 60, 5)], width=3)
    start_minute.grid(row=7, column=4, sticky=tk.W, padx=(40, 0))

    tk.Label(frame, text="Till Date:").grid(row=8, column=0, sticky=tk.W)
    end_date = DateEntry(frame, width=26, background='#109BAB', foreground='white', borderwidth=2)
    end_date.grid(row=8, column=1, pady=5, sticky=tk.W)

    tk.Label(frame, text="Till Time:").grid(row=8, column=2, sticky=tk.W)
    end_hour = ttk.Combobox(frame, values=[f"{i:02}" for i in range(24)], width=3)
    end_hour.grid(row=8, column=3, sticky=tk.W, padx=(0, 5))

    end_minute = ttk.Combobox(frame, values=[f"{i:02}" for i in range(0, 60, 5)], width=3)
    end_minute.grid(row=8, column=4, sticky=tk.W, padx=(40, 0))

    tk.Label(frame, text="Event Levels:").grid(row=9, column=0, sticky=tk.W)
    event_levels = []
    for i, level in enumerate(
            ["Critical", "Error", "Warning", "Information", "Verbose", "Audit Success", "Audit Failure"]):
        var = tk.IntVar()
        cb = tk.Checkbutton(frame, text=level, variable=var, width=26)
        cb.grid(row=9, column=i + 1, pady=2, sticky=tk.W)
        event_levels.append((level, var))

    for i in range(8):
        frame.columnconfigure(i, weight=1)

    # Output text
    output_text = scrolledtext.ScrolledText(frame, height=20, wrap=tk.WORD, background="white")
    output_text.grid(row=14, column=0, columnspan=6, pady=5, sticky=tk.NSEW)

    frame.rowconfigure(14, weight=1)

    # Buttons
    search_button = ttk.Button(frame, text="Search", style='TButton', command=start_search, width=10)
    search_button.grid(row=13, column=1, pady=5, sticky="ew", padx=5)

    clear_button = ttk.Button(frame, text="Clear", style='TButton', command=clear_fields, width=10)
    clear_button.grid(row=13, column=2, pady=5, sticky="ew", padx=5)

    root.mainloop()

# Function definitions (get_all_log_names, get_filtered_logs, clear_fields, toggle_remote)
def get_all_log_names(server):
    # Retrieves all log names on the specified server
    all_logs = []
    try:
        sources = ["Application", "System", "Security"]  # Common event log names
        for source in sources:
            hand = win32evtlog.OpenEventLog(server, source)
            if hand:
                all_logs.append(source)
                win32evtlog.CloseEventLog(hand)
    except pywintypes.error as e:
        print(f"Error fetching log names: {e}")
    return all_logs

def get_filtered_logs(server, log_name_keywords, event_type, event_category, source_name, keywords, start_date, end_date, max_events, event_levels):
    all_logs = get_all_log_names(server)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    logs = []

    for log_name in all_logs:
        try:
            hand = win32evtlog.OpenEventLog(server, log_name)
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for event in events:
                    if event.StringInserts:
                        for string in event.StringInserts:
                            if any(keyword in string for keyword in log_name_keywords.split(',')) and (start_date <= event.TimeGenerated <= end_date if start_date and end_date else True):
                                logs.append({
                                    "Log Name": log_name,
                                    "Event ID": event.EventID,
                                    "Time Generated": event.TimeGenerated,
                                    "Source Name": event.SourceName,
                                    "Event Type": event.EventType,
                                    "Event Category": event.EventCategory,
                                    "Event Data": event.StringInserts
                                })
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            print(f"Error processing log {log_name}: {e}")
            continue
    return logs

# Local or Remote selection
def toggle_remote(state):
    if state == "remote":
        remote_machine.config(state=tk.NORMAL)
    else:
        remote_machine.config(state=tk.DISABLED)


def clear_fields():
    global log_name, source_name, event_type, event_category, event_id, max_events, keywords, start_date, end_date, event_levels, remote_machine, selection, output_text

    # Clear Entry fields
    log_name.delete(0, tk.END)
    source_name.delete(0, tk.END)
    event_type.delete(0, tk.END)
    event_category.delete(0, tk.END)
    event_id.delete(0, tk.END)
    max_events.delete(0, tk.END)
    keywords.delete(0, tk.END)
    start_date.set_date(datetime.date.today())
    end_date.set_date(datetime.date.today())
    remote_machine.delete(0, tk.END)

    # Clear Radiobutton and disable remote machine field
    selection.set("local")
    toggle_remote("local")

    # Clear Checkbutton fields
    for _, var in event_levels:
        var.set(0)

    # Clear ScrolledText
    output_text.delete(1.0, tk.END)


if __name__ == "__main__":
    create_gui()
