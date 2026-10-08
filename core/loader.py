"""
=========================================================
SOC Weekly Report
Loader Module
=========================================================
"""

from pathlib import Path
import pandas as pd

from config.settings import (
    MASTER_RULE_FILE,
    DOMAIN_MAPPING_FILE,
    WEEKLY_DIR,
    DOMAIN_KEYWORD_SHEET,
    NONSPLUNK_FILE_PREFIX,
    TASK_FILE_PREFIX,
)
from utils.helpers import clean_severity, clean_nonsplunk_time, read_any_table


class DataLoader:

    def __init__(self):
        self.master_rule = None
        self.domain_mapping = None
        self.alert = None
        self.incident = None
        self.nonsplunk = None
        self.task = None
        self.week_folder = None

    # =====================================================
    # Pilih Folder Weekly
    # =====================================================

    def get_selected_week(self):
        week_list = sorted(
            [folder for folder in WEEKLY_DIR.iterdir() if folder.is_dir()],
            key=lambda x: int(x.name.lower().replace("w", ""))
        )
        if not week_list:
            raise Exception("Folder weekly kosong.")

        print("\nAvailable Weekly Folder")
        for i, folder in enumerate(week_list, start=1):
            print(f"{i}. {folder.name}")

        while True:
            selected = input("\nSelect Week (contoh: w29 atau 29): ").strip().lower()
            if selected.isdigit():
                selected = f"w{selected}"
            for folder in week_list:
                if folder.name.lower() == selected:
                    return folder
            print("Week tidak ditemukan, silakan coba lagi.")

    # =====================================================
    # Cari file berdasarkan prefix
    # =====================================================

    def find_file(self, folder, prefix):
        files = list(folder.glob(f"{prefix}*.xlsx"))
        if len(files) == 0:
            raise Exception(f"{prefix} tidak ditemukan.")
        return files[0]

    def find_file_optional(self, folder, prefix):
        """Sama seperti find_file, tapi tidak raise exception kalau tidak ada -
        dipakai untuk file opsional (alert non-Splunk, belum semua minggu punya)."""
        files = list(folder.glob(f"{prefix}*.xlsx"))
        return files[0] if files else None

    # =====================================================
    # Load Master Rule
    # =====================================================

    def load_master_rule(self):
        print("Loading Master Rules...")
        self.master_rule = pd.read_excel(MASTER_RULE_FILE)
        print(f"   {len(self.master_rule)} Rules Loaded")

    # =====================================================
    # Load Domain Mapping
    # =====================================================

    def load_domain_mapping(self):
        print("Loading Domain Mapping (opsional, hanya fallback untuk rule baru)...")

        if not DOMAIN_MAPPING_FILE.exists():
            print("   (tidak ditemukan - dilewati, Security_Domain sepenuhnya pakai kolom di Master_Rules_Splunk.xlsx)")
            self.domain_mapping = pd.DataFrame(columns=["Priority", "Keyword", "Security_Domain", "Security_Sub_Domain"])
            return

        excel = pd.ExcelFile(DOMAIN_MAPPING_FILE)

        if "Keyword_Mapping" not in excel.sheet_names:
            print("   [WARNING] Sheet 'Keyword_Mapping' tidak ditemukan - fallback klasifikasi dilewati.")
            self.domain_mapping = pd.DataFrame(columns=["Priority", "Keyword", "Security_Domain", "Security_Sub_Domain"])
            return

        self.domain_mapping = pd.read_excel(DOMAIN_MAPPING_FILE, sheet_name="Keyword_Mapping")
        print(f"   Keyword Rows : {len(self.domain_mapping)}")

    # =====================================================
    # Load Alert Non-Splunk (opsional, per minggu)
    # =====================================================

    def load_nonsplunk_from_file(self, filepath):
        xl = pd.ExcelFile(filepath)
        frames = []

        for sheet in xl.sheet_names:
            df = xl.parse(sheet)

            required = {"Alert Start Time", "Kategori Alert", "Severity", "Apakah dibuat tiket Ivanti?"}
            if not required.issubset(df.columns):
                print(f"   [SKIP] Sheet '{sheet}' di {filepath.name}: kolom wajib tidak lengkap.")
                continue

            df["Alert_Time_Std"] = df["Alert Start Time"].apply(clean_nonsplunk_time)
            df["Severity_Std"] = df["Severity"].apply(clean_severity)
            df["Source_Device"] = sheet
            df["Ticket_Status_Flag"] = df["Apakah dibuat tiket Ivanti?"].fillna("BELUM DIVERIFIKASI")

            keep_cols = ["Source_Device", "Alert_Time_Std", "Kategori Alert", "Deskripsi",
                         "Severity_Std", "Ticket_Status_Flag", "Reason", "No. Tiket Ivanti", "PIC"]
            keep_cols = [c for c in keep_cols if c in df.columns]
            frames.append(df[keep_cols])

        if not frames:
            return pd.DataFrame()
        return pd.concat(frames, ignore_index=True)

    # =====================================================
    # Load Task SOC (opsional, per minggu) - task pengecekan dari tim lain
    # yang TIDAK tercatat sebagai insiden ter-assign resmi.
    # =====================================================

    # =====================================================
    # Load CTI FortiRecon (opsional, per periode) - alert CTI eksternal
    # (Stealer Infection, EASM Change, dst) yang selama ini cuma di-track
    # manual di Excel tanpa reporting bulanan.
    # =====================================================

    def load_cti_fortirecon_from_file(self, filepath):
        df = read_any_table(filepath)

        rename_map = {
            "Tanggal Alert": "Alert_Date",
            "Jenis Alert": "Alert_Type",
            "Hostname/Domain": "Hostname_Domain",
            "Port": "Port",
            "Sistem / User Terdampak": "Affected_System_User",
            "Password": "_Password_Raw",  # DIHAPUS setelah dikonversi jadi indikator - JANGAN disimpan mentah
            "Category": "Category",
            "Hasil Pengecekan": "Verification_Result",
            "Status": "Status",
            "Incident Ticket": "Incident_Ticket",
            "Catatan": "Notes",
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

        required = {"Alert_Date", "Alert_Type"}
        missing = required - set(df.columns)
        if missing:
            print(f"   [SKIP] {filepath.name}: kolom wajib tidak lengkap (kurang: {missing})")
            return pd.DataFrame()

        # Coba format eksplisit "12-Jul-26" dulu (paling umum dari export FortiRecon),
        # baru fallback ke auto-detect kalau formatnya beda - supaya tidak selalu
        # kena warning "Could not infer format" dari pandas.
        try:
            df["Alert_Date"] = pd.to_datetime(df["Alert_Date"], format="%d-%b-%y")
        except (ValueError, TypeError):
            df["Alert_Date"] = pd.to_datetime(df["Alert_Date"], errors="coerce", dayfirst=True)

        # KEAMANAN: password asli TIDAK PERNAH disimpan/ditampilkan di laporan -
        # cukup indikator ada/tidaknya kredensial bocor, bukan nilainya.
        if "_Password_Raw" in df.columns:
            df["Password_Leaked"] = df["_Password_Raw"].notna() & (df["_Password_Raw"].astype(str).str.strip() != "")
            df = df.drop(columns=["_Password_Raw"])
        else:
            df["Password_Leaked"] = False

        for col in ["Verification_Result", "Status", "Category", "Alert_Type"]:
            if col not in df.columns:
                df[col] = "Tidak Diketahui"
            df[col] = df[col].fillna("Tidak Diketahui").replace("", "Tidak Diketahui")

        return df

    def load_task_from_file(self, filepath):
        df = read_any_table(filepath)

        # Kolom ASLI dari export Ivanti (dikonfirmasi dari data real user, 31 Jul 2026 -
        # BEDA dari asumsi awal berdasarkan screenshot). Mapping ke nama kanonik internal
        # supaya processor.py tidak perlu tahu nama kolom mentahnya.
        rename_map = {
            "TaskID": "Task",
            "status": "Status",
            "CreatedDateTime": "Created On",
            "CompleteDateTime": "Completed On",
            "AcceptedDateTime": "Accepted On",
        }
        df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

        required = {"Task", "Subject", "Status", "Owner", "Created On"}
        missing = required - set(df.columns)
        if missing:
            print(f"   [SKIP] {filepath.name}: kolom wajib tidak lengkap (kurang: {missing})")
            return pd.DataFrame()

        df["Created On"] = pd.to_datetime(df["Created On"], errors="coerce")

        if "Completed On" in df.columns:
            df["Completed On"] = pd.to_datetime(df["Completed On"], errors="coerce")
        else:
            df["Completed On"] = pd.NaT

        # Prioritas: pakai "Duration Complete (Minutes)" yang SUDAH DIHITUNG Ivanti
        # (kemungkinan sudah memperhitungkan jam kerja/exclusion tertentu) - jangan
        # hitung ulang dari selisih tanggal mentah kalau kolom ini tersedia, supaya
        # konsisten dengan apa yang dilihat tim SOC di Ivanti langsung.
        if "Duration Complete (Minutes)" in df.columns:
            df["Turnaround_sec"] = pd.to_numeric(df["Duration Complete (Minutes)"], errors="coerce") * 60
        elif "Completed On" in df.columns:
            df["Turnaround_sec"] = (df["Completed On"] - df["Created On"]).dt.total_seconds()
        else:
            df["Turnaround_sec"] = None

        # SLA breach - Ivanti sudah punya kolom ini sendiri (Response_meet/breach,
        # Resolution_meet/breach) - dipakai langsung, tidak perlu dihitung ulang.
        df["Response_SLA"] = df.get("Response_meet/breach", pd.Series(dtype=object))
        df["Resolution_SLA"] = df.get("Resolution_meet/breach", pd.Series(dtype=object))

        # Kolom tim peminta (Requestor_Team) TIDAK ADA di export Ivanti saat ini -
        # kalau nanti ditambahkan, otomatis kepakai; kalau tidak, breakdown per-tim
        # dilewati (lihat build_task_summary).
        if "Requestor_Team" not in df.columns:
            df["Requestor_Team"] = "Tidak Diketahui"

        return df

    # =====================================================
    # Load Weekly Data
    # =====================================================

    def load_weekly_data(self):
        self.week_folder = self.get_selected_week()
        print(f"\nLoading Week : {self.week_folder.name}")

        alert_file = self.find_file(self.week_folder, "alert_splunk")
        incident_file = self.find_file(self.week_folder, "insiden_ivanti")

        print(f"Alert File    : {alert_file.name}")
        print(f"Incident File : {incident_file.name}")

        self.alert = pd.read_excel(alert_file)
        self.incident = pd.read_excel(incident_file)

        print(f"Alert Rows    : {len(self.alert)}")
        print(f"Incident Rows : {len(self.incident)}")

        nonsplunk_file = self.find_file_optional(self.week_folder, NONSPLUNK_FILE_PREFIX)
        if nonsplunk_file:
            print(f"NonSplunk File: {nonsplunk_file.name}")
            raw_ns = self.load_nonsplunk_from_file(nonsplunk_file)

            # File non-Splunk boleh berisi rentang tanggal lebih lebar dari 1 minggu
            # (mis. baru mulai di-list mid-week, atau satu file dipakai untuk beberapa
            # minggu sekaligus). Supaya laporan MINGGUAN tetap ketat per periode -
            # dan tidak "mencuri" data minggu lain - batasi ke rentang tanggal alert
            # Splunk minggu ini. Baris yang terbuang tetap aman: akan otomatis ke-
            # hitung saat laporan mingguan minggu yang sesuai / laporan bulanan dibuat.
            alert_dates = pd.to_datetime(self.alert["Alert Time"], errors="coerce").dropna()
            if len(raw_ns) > 0 and len(alert_dates) > 0:
                week_start, week_end = alert_dates.min().normalize(), alert_dates.max().normalize() + pd.Timedelta(days=1)
                in_range = raw_ns["Alert_Time_Std"].between(week_start, week_end, inclusive="left")
                self.nonsplunk = raw_ns[in_range].reset_index(drop=True)
                excluded = len(raw_ns) - len(self.nonsplunk)
                if excluded > 0:
                    print(f"   [INFO] {excluded} baris non-Splunk di luar rentang minggu ini "
                          f"({week_start.date()} - {(week_end - pd.Timedelta(days=1)).date()}) - "
                          "dilewati dari laporan mingguan ini, tetap terhitung di laporan bulanan/minggu yang sesuai.")
            else:
                self.nonsplunk = raw_ns

            print(f"NonSplunk Rows: {len(self.nonsplunk)} (dari {len(raw_ns)} baris di file)")
        else:
            print("NonSplunk File: (tidak ada - dilewati, laporan tetap jalan)")
            self.nonsplunk = pd.DataFrame()

        task_file = self.find_file_optional(self.week_folder, TASK_FILE_PREFIX)
        if task_file:
            print(f"Task File     : {task_file.name}")
            raw_task = self.load_task_from_file(task_file)

            alert_dates = pd.to_datetime(self.alert["Alert Time"], errors="coerce").dropna()
            if len(raw_task) > 0 and len(alert_dates) > 0:
                week_start, week_end = alert_dates.min().normalize(), alert_dates.max().normalize() + pd.Timedelta(days=1)
                in_range = raw_task["Created On"].between(week_start, week_end, inclusive="left")
                self.task = raw_task[in_range].reset_index(drop=True)
            else:
                self.task = raw_task
            print(f"Task Rows     : {len(self.task)}")
        else:
            print("Task File     : (tidak ada - dilewati, laporan tetap jalan)")
            self.task = pd.DataFrame()

    # =====================================================
    # Load Monthly Data
    # =====================================================
    # Digabung dari SEMUA folder weekly yang ada, lalu difilter berdasarkan
    # tanggal ASLI di dalam data (Alert Time / Created On / Alert_Time_Std) -
    # bukan nama folder, karena satu minggu bisa lintas 2 bulan.

    def load_monthly_data(self, year, month):
        print(f"\nLoading Monthly Data : {year}-{month:02d}")

        week_list = [f for f in WEEKLY_DIR.iterdir() if f.is_dir()]
        if not week_list:
            raise Exception("Folder weekly kosong.")

        alert_frames, incident_frames, nonsplunk_frames, task_frames = [], [], [], []

        for folder in week_list:
            try:
                alert_file = self.find_file(folder, "alert_splunk")
                incident_file = self.find_file(folder, "insiden_ivanti")
            except Exception:
                print(f"   [SKIP] {folder.name}: file alert/incident tidak lengkap")
                continue

            alert_frames.append(pd.read_excel(alert_file))
            incident_frames.append(pd.read_excel(incident_file))

            nonsplunk_file = self.find_file_optional(folder, NONSPLUNK_FILE_PREFIX)
            if nonsplunk_file:
                nonsplunk_frames.append(self.load_nonsplunk_from_file(nonsplunk_file))

            task_file = self.find_file_optional(folder, TASK_FILE_PREFIX)
            if task_file:
                task_frames.append(self.load_task_from_file(task_file))

        all_alert = pd.concat(alert_frames, ignore_index=True)
        all_incident = pd.concat(incident_frames, ignore_index=True)

        all_alert["Alert Time"] = pd.to_datetime(all_alert["Alert Time"], errors="coerce")
        all_incident["Created On"] = pd.to_datetime(all_incident["Created On"], errors="coerce")

        self.alert = all_alert[
            (all_alert["Alert Time"].dt.year == year) & (all_alert["Alert Time"].dt.month == month)
        ].drop_duplicates().reset_index(drop=True)

        self.incident = all_incident[
            (all_incident["Created On"].dt.year == year) & (all_incident["Created On"].dt.month == month)
        ].drop_duplicates(subset=["Incident"]).reset_index(drop=True)

        if nonsplunk_frames:
            all_nonsplunk = pd.concat(nonsplunk_frames, ignore_index=True)
            self.nonsplunk = all_nonsplunk[
                (all_nonsplunk["Alert_Time_Std"].dt.year == year) &
                (all_nonsplunk["Alert_Time_Std"].dt.month == month)
            ].reset_index(drop=True)
        else:
            self.nonsplunk = pd.DataFrame()

        if task_frames:
            all_task = pd.concat(task_frames, ignore_index=True)
            self.task = all_task[
                (all_task["Created On"].dt.year == year) & (all_task["Created On"].dt.month == month)
            ].drop_duplicates(subset=["Task"]).reset_index(drop=True)
        else:
            self.task = pd.DataFrame()

        print(f"Alert Rows    : {len(self.alert)} (dari total gabungan {len(all_alert)} lintas semua folder weekly)")
        print(f"Incident Rows : {len(self.incident)} (dari total gabungan {len(all_incident)} lintas semua folder weekly)")
        print(f"NonSplunk Rows: {len(self.nonsplunk)}")
        print(f"Task Rows     : {len(self.task)}")

        if len(self.alert) == 0 and len(self.incident) == 0:
            raise Exception(
                f"Tidak ada data untuk bulan {year}-{month:02d}. "
                "Cek apakah folder weekly yang relevan sudah tersedia di input/weekly/."
            )

    # =====================================================
    # Main Loader
    # =====================================================

    def load(self, mode="weekly", year=None, month=None):
        self.load_master_rule()
        self.load_domain_mapping()

        if mode == "monthly":
            self.load_monthly_data(year, month)
            period_label = f"{year}-{month:02d}"
        else:
            self.load_weekly_data()
            period_label = self.week_folder.name

        return {
            "master_rule": self.master_rule,
            "domain_mapping": self.domain_mapping,
            "alert": self.alert,
            "incident": self.incident,
            "nonsplunk": self.nonsplunk,
            "task": self.task,
            "week": period_label
        }


def load_data(mode="weekly", year=None, month=None):
    loader = DataLoader()
    return loader.load(mode=mode, year=year, month=month)
