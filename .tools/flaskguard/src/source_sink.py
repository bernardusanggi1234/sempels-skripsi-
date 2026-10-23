"""Katalog deklaratif source dan sink injeksi untuk aplikasi Flask.

Tidak menjalankan kode target, mencocokkan AST, atau mempropagasi taint.
Seluruh sink adalah kandidat, bukan bukti kerentanan. Path Traversal tidak
termasuk cakupan. Gunakan ``from src.source_sink import SOURCES, SINKS``.

Nama pada patterns adalah nama kanonis setelah resolusi alias impor/tipe
receiver. Misalnya ``users.find`` hanya cocok dengan Collection.find jika
``users`` terbukti merupakan koleksi PyMongo; nama method saja tidak cukup.
DBAPI merupakan label protokol PEP 249, bukan modul yang bisa diimpor.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class SourceSpec:
    """Input Flask: atribut/method, modul asal, pola kanonis, dan maknanya.

    Taint melekat pada nilai hasil akses, termasuk subscript, get(), getlist(),
    dan iterasi container; bukan pada string nama parameter yang dicari.
    """

    name: str
    module: str
    patterns: tuple[str, ...]
    access: Literal["attribute", "call"]
    description: str


@dataclass(frozen=True)
class SensitiveParameter:
    """Posisi sensitif: indeks nol-based tanpa self, keyword, dan perannya.

    index=None berarti tidak ada argumen posisi (misalnya state receiver).
    keywords=() berarti positional-only atau bukan parameter pemanggilan.
    Untuk assignment, slot sintetis 0=key, 1=value mengikuti __setitem__.
    """

    index: int | None
    keywords: tuple[str, ...]
    role: str


@dataclass(frozen=True)
class SinkSpec:
    """Metadata sink, tanpa implementasi pemeriksaan.

    name: nama fungsi/method; module: modul atau protokol asal.
    category: salah satu key SINKS; patterns: target kanonis yang setara.
    sensitive_parameters: lokasi data yang perlu diperiksa.
    conditions: kontrak semantik untuk tracker; cakupan implementasi aktual
    didokumentasikan pada docs/architecture.md (bukan semua kondisi terbukti).
    required_keywords: syarat nilai keyword, misalnya shell=True. Nilai yang
    tidak diketahui harus dianggap perlu ditinjau, bukan otomatis aman.
    kind membedakan call dari assignment dan render dari state receiver.
    """

    name: str
    module: str
    category: str
    patterns: tuple[str, ...]
    sensitive_parameters: tuple[SensitiveParameter, ...]
    conditions: tuple[str, ...]
    required_keywords: tuple[tuple[str, object], ...] = ()
    kind: Literal["call", "receiver_call", "subscript_assignment"] = "call"

    @property
    def rule_id(self) -> str:
        """Stable ID derived from the explicit canonical API, not its line number."""
        return "sink:" + self.patterns[0]


SOURCES: dict[str, SourceSpec] = {
    f"request.{name}": SourceSpec(
        name, "flask", (f"flask.request.{name}",), "attribute", description
    )
    for name, description in (
        ("args", "Parameter query URL."),
        ("form", "Data form pada body permintaan."),
        ("json", "Body JSON, termasuk dict/list bersarang."),
        ("cookies", "Cookie yang dikirim klien."),
        ("headers", "Header permintaan HTTP dari klien."),
        ("values", "Gabungan parameter args/form sesuai perilaku Flask."),
    )
}
"""Enam source utama Flask; tidak menyertakan input terminal input().

Parser perlu menormalisasi request/req/flask.request ke flask.request setelah
memeriksa impor dan shadowing. Akses get()/subscript mewarisi source atribut.
"""

SOURCES["request.get_json"] = SourceSpec(
    "get_json", "flask", ("flask.request.get_json",), "call",
    "Padanan method untuk membaca body JSON; nilai kembalian tidak terpercaya.",
)


# Only normal return values are constrained. This is not a universal validator
# for business logic or other vulnerability classes.
NUMERIC_SANITIZERS = {
    name: frozenset({"SQL Injection", "Command Injection", "Code Injection", "SSTI", "NoSQL Injection", "Header Injection"})
    for name in ("builtins.int", "builtins.float")
}


SINKS: dict[str, tuple[SinkSpec, ...]] = {
    "SQL Injection": (
        SinkSpec(
            "execute", "DBAPI", "SQL Injection", ("DBAPI.Cursor.execute",),
            (SensitiveParameter(0, (), "sql"),),
            ("Receiver adalah cursor/connection DB-API; keyword bergantung driver.",
             "Input mengendalikan teks SQL, bukan sekadar nilai parameter binding."),
        ),
        SinkSpec(
            "executemany", "DBAPI", "SQL Injection", ("DBAPI.Cursor.executemany",),
            (SensitiveParameter(0, (), "sql"),),
            ("Receiver adalah cursor DB-API; periksa teks SQL, bukan kumpulan nilai binding.",),
        ),
        SinkSpec(
            "execute", "sqlalchemy", "SQL Injection",
            ("sqlalchemy.engine.Connection.execute", "sqlalchemy.orm.Session.execute"),
            (SensitiveParameter(0, ("statement",), "sql_statement"),),
            ("Termasuk db.execute bila db ter-resolve ke Connection/Session.",
             "Periksa asal teks TextClause; ekspresi ORM dan bound values tidak otomatis rentan.",
             "String mentah diterima atau ditolak bergantung API/versi."),
        ),
        SinkSpec(
            "exec_driver_sql", "sqlalchemy", "SQL Injection",
            ("sqlalchemy.engine.Connection.exec_driver_sql",),
            (SensitiveParameter(0, ("statement",), "sql"),),
            ("Input mengendalikan teks SQL yang dikirim ke driver.",),
        ),
        SinkSpec(
            "text", "sqlalchemy", "SQL Injection",
            ("sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text"),
            (SensitiveParameter(0, ("text",), "sql"),),
            ("Konstruktor SQL tekstual, belum eksekusi; lacak hasilnya ke execute.",
             "Binding tidak membersihkan input yang sudah diinterpolasi ke teks SQL."),
        ),
    ),
    "Command Injection": (
        SinkSpec(
            "system", "os", "Command Injection", ("os.system",),
            (SensitiveParameter(0, (), "shell_command"),),
            ("Perintah diinterpretasikan oleh shell.",),
        ),
        SinkSpec(
            "popen", "os", "Command Injection", ("os.popen",),
            (SensitiveParameter(0, ("cmd",), "shell_command"),),
            ("Perintah diinterpretasikan oleh shell.",),
        ),
        *(
            SinkSpec(
                name, "subprocess", "Command Injection", (f"subprocess.{name}",),
                (SensitiveParameter(0, ("args",), "shell_command"),),
                ("Shell injection memerlukan shell aktif; tanpa shell, kendali executable/argumen dilaporkan terpisah untuk review.",),
                required_keywords=(("shell", True),),
            )
            for name in ("run", "Popen", "call", "check_call", "check_output")
        ),
        *(
            SinkSpec(
                name, "subprocess", "Command Injection", (f"subprocess.{name}",),
                (SensitiveParameter(0, ("cmd",), "shell_command"),),
                ("API ini menjalankan command melalui shell secara internal.",),
            )
            for name in ("getoutput", "getstatusoutput")
        ),
    ),
    "Code Injection": tuple(
        SinkSpec(
            name, "builtins", "Code Injection", (f"builtins.{name}",),
            (SensitiveParameter(0, (), "python_code"),),
            ("Builtin tidak di-shadow; input mengendalikan source kode yang dieksekusi.",),
        )
        for name in ("eval", "exec")
    ),
    "SSTI": (
        SinkSpec(
            "render_template_string", "flask", "SSTI",
            ("flask.render_template_string", "flask.templating.render_template_string"),
            (SensitiveParameter(0, ("source",), "template_source"),),
            ("Periksa source template; nilai context pada template tetap bukan SSTI.",),
        ),
        SinkSpec(
            "Template", "jinja2", "SSTI", ("jinja2.Template", "jinja2.environment.Template"),
            (SensitiveParameter(0, ("source",), "template_source"),),
            ("Kompilasi template; simpan asal source pada objek hasil untuk render berikutnya.",),
        ),
        SinkSpec(
            "from_string", "jinja2", "SSTI", ("jinja2.Environment.from_string",),
            (SensitiveParameter(0, ("source",), "template_source"),),
            ("Receiver adalah Environment Jinja; hasil menyimpan asal source template.",),
        ),
        SinkSpec(
            "render", "jinja2", "SSTI", ("jinja2.Template.render",),
            (SensitiveParameter(None, (), "receiver.template_source"),),
            ("Taint harus berasal dari source template pada receiver, bukan argumen context.",),
            kind="receiver_call",
        ),
    ),
    "NoSQL Injection": (
        *(
            SinkSpec(
                name, "pymongo", "NoSQL Injection", (f"pymongo.collection.Collection.{name}",),
                (SensitiveParameter(0, ("filter",), "query_filter"),),
                ("Receiver adalah Collection PyMongo.",
                 "Input mengendalikan struktur/operator filter (misalnya raw dict dari JSON); "
                 "nilai scalar pada field tetap tidak otomatis merupakan injeksi."),
            )
            for name in (
                "find", "find_one", "count_documents", "delete_one", "delete_many",
                "replace_one", "find_one_and_delete", "find_one_and_replace",
            )
        ),
        *(
            SinkSpec(
                name, "pymongo", "NoSQL Injection", (f"pymongo.collection.Collection.{name}",),
                (SensitiveParameter(0, ("filter",), "query_filter"),
                 SensitiveParameter(1, ("update",), "update_operators_or_pipeline")),
                ("Receiver adalah Collection PyMongo; input mengendalikan struktur/operator "
                 "filter atau update, bukan hanya nilai scalar di struktur tetap.",),
            )
            for name in ("update_one", "update_many", "find_one_and_update")
        ),
        SinkSpec(
            "aggregate", "pymongo", "NoSQL Injection", ("pymongo.collection.Collection.aggregate",),
            (SensitiveParameter(0, ("pipeline",), "aggregation_pipeline"),),
            ("Input mengendalikan stage/operator pipeline pada Collection PyMongo.",),
        ),
        SinkSpec(
            "distinct", "pymongo", "NoSQL Injection", ("pymongo.collection.Collection.distinct",),
            (SensitiveParameter(1, ("filter",), "query_filter"),),
            ("Filter berada di indeks 1; key di indeks 0 bukan filter.",
             "Input mengendalikan struktur/operator filter pada Collection PyMongo."),
        ),
    ),
    "Header Injection": (
        *(
            SinkSpec(
                name, "werkzeug", "Header Injection", (f"werkzeug.datastructures.Headers.{name}",),
                (SensitiveParameter(0, ("key",), "header_name"),
                 SensitiveParameter(1, ("value",), "header_value")),
                ("Receiver adalah Headers milik response, bukan request headers.",
                 "Periksa CR/LF serta validasi framework; taint saja tidak membuktikan response splitting."),
            )
            for name in ("add", "set")
        ),
        SinkSpec(
            "__setitem__", "werkzeug", "Header Injection",
            ("werkzeug.datastructures.Headers.__setitem__",),
            (SensitiveParameter(0, (), "header_name"), SensitiveParameter(1, (), "header_value")),
            ("Normalisasi response.headers[key] = value menjadi slot key/value sintetis.",
             "Receiver adalah response Headers; pertimbangkan validasi CR/LF framework."),
            kind="subscript_assignment",
        ),
        SinkSpec(
            "Response", "flask", "Header Injection", ("flask.Response", "flask.wrappers.Response"),
            (SensitiveParameter(2, ("headers",), "header_mapping"),),
            ("Periksa nama/nilai header dari mapping atau pasangan header yang tidak terpercaya.",
             "Validasi framework dapat menolak CR/LF sehingga kandidat tidak selalu exploitable."),
        ),
        SinkSpec(
            "Response", "werkzeug", "Header Injection", ("werkzeug.wrappers.Response",),
            (SensitiveParameter(2, ("headers",), "header_mapping"),),
            ("Periksa nama/nilai header dan validasi CR/LF pada framework.",),
        ),
    ),
}
"""Sink dikelompokkan ke tepat enam kategori injeksi.

Indeks tidak menghitung self. Tidak ada wildcard *.execute/*.find agar method
yang kebetulan sama namanya tidak otomatis dianggap sink. Katalog ini mencakup
API umum, bukan seluruh API/versi/driver Python. Pola tambahan memerlukan rule
dan evaluasi tersendiri. Engine mengonsumsi katalog ini; kondisi bahasa alami
tetap metadata, dengan subset pemeriksaan eksplisit di engine/taint_engine.py.
"""
