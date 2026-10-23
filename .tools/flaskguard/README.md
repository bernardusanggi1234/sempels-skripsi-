# FlaskGuard 0.1.1

Snapshot scanner AST/taint Python Flask untuk workflow repository ini.
Scanner membaca source tanpa menjalankan aplikasi target. Analisis utama
intraprosedural; scan folder bukan analisis lintas modul.

Kategori: SQL, Command, Code, SSTI, NoSQL, dan Header/CRLF Injection.
Temuan adalah kandidat statis, bukan bukti eksploitasi. Baca coverage_issues
dan analysis_status pada JSON.

Instalasi: python -m pip install ./.tools/flaskguard
Scan: flaskguard scan Vulnerable-Flask-App-main/ --json --output flaskguard-report.json --error

Exit 1 berarti kandidat ditemukan dengan --error. Exit 2 berarti ada
error/berkas dilewati; --strict juga menjadikan cakupan parsial exit 2.
Workflow sengaja tetap gagal ketika contoh rentan menghasilkan kandidat.
Laporan tersimpan sebagai artifact walaupun scan menghasilkan exit 1.

Snapshot perlu diperbarui secara eksplisit ketika engine berubah;
source di komputer pengembang tidak otomatis tersinkron ke GitHub.
