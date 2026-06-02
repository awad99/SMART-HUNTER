"""
scan_stats.py — نظام تتبع وإحصاء عمليات قاعدة البيانات لكل فحص
يُستدعى من scan files في نهاية كل فحص لطباعة تقرير مفصل.
"""
from collections import defaultdict
from datetime import datetime

# الجداول بالترتيب المنطقي للعرض
_ALL_TABLES = [
    'scans',
    'vulnerabilities',
    'features',
    'raw_responses',
    'redirect_chain',
    'response_headers',
    'cookies',
    'forms',
    'endpoints',
    'fuzzing_results',
    'subdomains',
    'scan_reports',
    'discovery_domains',
    'discovery_parameters',
]


class ScanStats:
    """
    تتبع إحصائيات عمليات قاعدة البيانات أثناء الفحص.

    الاستخدام:
        stats = ScanStats(scan_id)
        stats.add('vulnerabilities', 3)
        stats.update('scans', 1)
        stats.print_summary()
    """

    def __init__(self, scan_id: str):
        self.scan_id   = scan_id
        self.start_time = datetime.now()
        self._counts   = defaultdict(lambda: {'added': 0, 'modified': 0, 'deleted': 0})

    # ── Record methods ──────────────────────────────────────────
    def add(self, table: str, count: int = 1) -> 'ScanStats':
        """تسجيل إضافة سجلات جديدة."""
        if count > 0:
            self._counts[table]['added'] += count
        return self   # للـ chaining

    def update(self, table: str, count: int = 1) -> 'ScanStats':
        """تسجيل تعديل سجلات موجودة."""
        if count > 0:
            self._counts[table]['modified'] += count
        return self

    def delete(self, table: str, count: int = 1) -> 'ScanStats':
        """تسجيل حذف سجلات."""
        if count > 0:
            self._counts[table]['deleted'] += count
        return self

    # ── Summary ─────────────────────────────────────────────────
    def total_added(self) -> int:
        return sum(v['added'] for v in self._counts.values())

    def total_modified(self) -> int:
        return sum(v['modified'] for v in self._counts.values())

    def total_deleted(self) -> int:
        return sum(v['deleted'] for v in self._counts.values())

    def duration(self) -> str:
        delta = datetime.now() - self.start_time
        m, s  = divmod(int(delta.total_seconds()), 60)
        return f"{m}m {s}s" if m else f"{s}s"

    # ── Pretty printer ───────────────────────────────────────────
    def print_summary(self):
        """
        طباعة جدول إحصائي مرتب في نهاية الفحص.
        """
        w_table, w_num = 22, 8
        line_len = w_table + w_num * 3 + 11

        border_top  = '+' + '-'*(w_table+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+'
        border_head = '+' + '='*(w_table+2) + '+' + '='*(w_num+2) + '+' + '='*(w_num+2) + '+' + '='*(w_num+2) + '+'
        border_mid  = '+' + '-'*(w_table+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+'
        border_bot  = '+' + '-'*(w_table+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+' + '-'*(w_num+2) + '+'

        def row(name, added, modified, deleted, sep='|'):
            n = name[:w_table].ljust(w_table)
            a = str(added).rjust(w_num)
            m = str(modified).rjust(w_num)
            d = str(deleted).rjust(w_num)
            return f"{sep} {n} {sep} {a} {sep} {m} {sep} {d} {sep}"

        print(f"\n{border_top}")
        print(f"|{'SCAN DATABASE STATISTICS':^{line_len}}|")
        print(f"|{'Scan ID: ' + self.scan_id:^{line_len}}|")
        print(border_head)
        print(row('Table', 'Added', 'Modified', 'Deleted'))
        print(border_head)

        tables = list(_ALL_TABLES)
        # أضف أي جدول ظهر في الـ stats ولم يكن في القائمة
        for t in self._counts:
            if t not in tables:
                tables.append(t)

        for i, table in enumerate(tables):
            c = self._counts.get(table, {'added': 0, 'modified': 0, 'deleted': 0})
            print(row(table, c['added'], c['modified'], c['deleted']))
            if i < len(tables) - 1:
                print(border_mid)

        print(border_head)
        print(row('TOTAL', self.total_added(), self.total_modified(), self.total_deleted()))
        print(border_bot)
        print(f"  Duration: {self.duration()}   |   Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def save_to_file(self, path: str):
        """حفظ ملخص الإحصاءات إلى ملف نصي."""
        import io, sys
        old = sys.stdout
        sys.stdout = buf = io.StringIO()
        self.print_summary()
        sys.stdout = old
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(buf.getvalue())
        except Exception as e:
            print(f"[-] ScanStats: Could not save log to {path}: {e}")
