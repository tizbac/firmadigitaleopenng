#include "mainwindow.h"
#include "pdfpreview.h"
#include "pades.h"
#include "p7m.h"
#include "x509util.h"

#include <QTabWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QPlainTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QFile>
#include <QApplication>
#include <QFrame>
#include <QThread>
#include <QTimer>
#include <QProgressDialog>
#include <QMetaType>

#include <algorithm>
#include <map>

#include "tslparser.h"

namespace {

bool readFileBytes(const QString &path, std::vector<unsigned char> &out,
                   std::string &error)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        error = "impossibile aprire " + path.toStdString();
        return false;
    }
    const QByteArray data = f.readAll();
    out.assign(data.constData(), data.constData() + data.size());
    return true;
}

bool writeFileBytes(const QString &path, const std::vector<unsigned char> &bytes,
                    std::string &error)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        error = "impossibile scrivere " + path.toStdString();
        return false;
    }
    f.write(reinterpret_cast<const char *>(bytes.data()),
            static_cast<qint64>(bytes.size()));
    return true;
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Firma digitale OpenSource - Tiziano Bacocco"));
    resize(1150, 800);

    m_tabs = new QTabWidget(this);
    m_tabs->addTab(buildPadesTab(), tr("Firma PDF (PAdES)"));
    m_tabs->addTab(buildP7mTab(), tr("Firma File (P7M / CAdES)"));
    m_tabs->addTab(buildVerifyTab(), tr("Verifica Firma (P7M)"));
    setCentralWidget(m_tabs);

    // PKCS#11 worker: slot enumeration and signing run on a dedicated
    // thread because real tokens take seconds per C_* call (PIN entry on
    // the token display, USB round trips) and must not freeze the UI.
    qRegisterMetaType<fdo::Pkcs11Slot>();
    qRegisterMetaType<std::vector<fdo::Pkcs11Slot>>();
    qRegisterMetaType<Pkcs11Worker::SignParams>();

    m_p11Thread = new QThread(this);
    m_p11Worker = new Pkcs11Worker;
    m_p11Worker->moveToThread(m_p11Thread);
    connect(m_p11Thread, &QThread::finished, m_p11Worker, &QObject::deleteLater);
    m_p11Thread->start();
    connect(this, &MainWindow::p11EnumerateRequested, m_p11Worker,
            &Pkcs11Worker::enumerate);
    connect(this, &MainWindow::p11SignRequested, m_p11Worker,
            &Pkcs11Worker::sign);
    connect(m_p11Worker, &Pkcs11Worker::enumerated, this,
            &MainWindow::onSlotsEnumerated);
    connect(m_p11Worker, &Pkcs11Worker::signFinished, this,
            &MainWindow::onSignFinished);

    m_slotDebounce = new QTimer(this);
    m_slotDebounce->setSingleShot(true);
    m_slotDebounce->setInterval(300);
    connect(m_slotDebounce, &QTimer::timeout, this,
            &MainWindow::issuePendingSlotQueries);

    // Default PKCS#11 module + initial slot detection.
    const QString defLib = defaultP11Lib();
    m_p11Lib->setText(defLib);
    m_p7mLib->setText(defLib);
    connect(m_p11Lib, &QLineEdit::textChanged, this,
            [this](const QString &) { detectSlots(m_p11Lib, m_p11Slot, m_p11Slots); });
    connect(m_p7mLib, &QLineEdit::textChanged, this,
            [this](const QString &) { detectSlots(m_p7mLib, m_p7mSlot, m_p7mSlots); });
    detectSlots(m_p11Lib, m_p11Slot, m_p11Slots);
    detectSlots(m_p7mLib, m_p7mSlot, m_p7mSlots);
}

MainWindow::~MainWindow()
{
    if (m_p11Thread) {
        m_p11Thread->quit();
        m_p11Thread->wait();
    }
}

QWidget *MainWindow::buildPadesTab()
{
    auto *tab = new QWidget;
    auto *root = new QHBoxLayout(tab);

    // Left: controls
    auto *left = new QWidget;
    left->setFixedWidth(400);
    auto *lv = new QVBoxLayout(left);

    lv->addWidget(new QLabel(tr("PDF da firmare:")));
    {
        auto *row = new QHBoxLayout;
        m_pdfInput = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browsePdfInput);
        row->addWidget(m_pdfInput, 1);
        row->addWidget(b);
        lv->addLayout(row);
    }

    lv->addWidget(new QLabel(tr("File firmato:")));
    {
        auto *row = new QHBoxLayout;
        m_pdfOutput = new QLineEdit;
        auto *b = new QPushButton(tr("Salva..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browsePdfOutput);
        row->addWidget(m_pdfOutput, 1);
        row->addWidget(b);
        lv->addLayout(row);
    }

    lv->addWidget(new QLabel(tr("Modulo PKCS#11:")));
    {
        auto *row = new QHBoxLayout;
        m_p11Lib = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseP11Lib);
        row->addWidget(m_p11Lib, 1);
        row->addWidget(b);
        lv->addLayout(row);
    }

    lv->addWidget(new QLabel(tr("Slot:")));
    m_p11Slot = new QComboBox;
    lv->addWidget(m_p11Slot);

    lv->addWidget(new QLabel(tr("PIN:")));
    m_p11Pin = new QLineEdit;
    m_p11Pin->setEchoMode(QLineEdit::Password);
    lv->addWidget(m_p11Pin);

    auto *line = new QFrame;
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    lv->addWidget(line);

    m_visible = new QCheckBox(tr("Firma visibile (disegna sul documento)"));
    m_visible->setChecked(true);
    lv->addWidget(m_visible);

    lv->addWidget(new QLabel(tr("Prefisso firma:")));
    m_visibleText = new QLineEdit("Firmato digitalmente da ");
    lv->addWidget(m_visibleText);

    lv->addWidget(new QLabel(tr("Pagina (da 0):")));
    m_page = new QSpinBox;
    m_page->setRange(0, 999);
    lv->addWidget(m_page);

    m_signPdf = new QPushButton(tr("Firma PDF"));
    connect(m_signPdf, &QPushButton::clicked, this, &MainWindow::signPdf);
    lv->addWidget(m_signPdf);

    m_pdfStatus = new QLabel;
    m_pdfStatus->setWordWrap(true);
    lv->addWidget(m_pdfStatus);

    lv->addStretch(1);

    // Right: PDF preview in a scroll area
    m_preview = new fdo::PdfPreview;
    auto *scroll = new QScrollArea;
    scroll->setWidget(m_preview);
    scroll->setWidgetResizable(false);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    connect(m_preview, &fdo::PdfPreview::boxChanged, this,
            [this](bool hasBox) {
                if (hasBox) {
                    m_boxLabel->setText(tr("Riquadro (pt PDF): %1 %2  %3 %4")
                                            .arg(int(m_preview->boxX1()),
                                                 int(m_preview->boxY1()))
                                            .arg(int(m_preview->boxX2()),
                                                 int(m_preview->boxY2())));
                } else {
                    m_boxLabel->setText(tr("Nessun riquadro firma selezionato"));
                }
            });
    connect(m_preview, &fdo::PdfPreview::pageChanged, this,
            [this](int) {});
    connect(m_page, qOverload<int>(&QSpinBox::valueChanged), m_preview,
            &fdo::PdfPreview::setPage);

    m_boxLabel = new QLabel(tr("Nessun riquadro firma selezionato"));

    auto *rv = new QVBoxLayout;
    rv->addWidget(scroll, 1);
    rv->addWidget(m_boxLabel);

    root->addWidget(left);
    auto *right = new QWidget;
    right->setLayout(rv);
    right->setMaximumWidth(720);
    root->addWidget(right, 1);

    return tab;
}

QWidget *MainWindow::buildP7mTab()
{
    auto *tab = new QWidget;
    auto *outer = new QVBoxLayout(tab);
    outer->setContentsMargins(16, 16, 16, 16);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    {
        auto *row = new QHBoxLayout;
        m_fileInput = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseFileInput);
        row->addWidget(m_fileInput, 1);
        row->addWidget(b);
        form->addRow(tr("File da firmare:"), row);
    }
    {
        auto *row = new QHBoxLayout;
        m_fileOutput = new QLineEdit;
        auto *b = new QPushButton(tr("Salva..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseFileOutput);
        row->addWidget(m_fileOutput, 1);
        row->addWidget(b);
        form->addRow(tr("Output (.p7m):"), row);
    }
    {
        auto *row = new QHBoxLayout;
        m_p7mLib = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseP11Lib);
        row->addWidget(m_p7mLib, 1);
        row->addWidget(b);
        form->addRow(tr("Modulo PKCS#11:"), row);
    }
    m_p7mSlot = new QComboBox;
    form->addRow(tr("Slot:"), m_p7mSlot);

    m_p7mPin = new QLineEdit;
    m_p7mPin->setEchoMode(QLineEdit::Password);
    form->addRow(tr("PIN:"), m_p7mPin);

    m_signFile = new QPushButton(tr("Firma File (P7M)"));
    connect(m_signFile, &QPushButton::clicked, this, &MainWindow::signFile);
    form->addRow(m_signFile);

    m_fileStatus = new QLabel;
    m_fileStatus->setWordWrap(true);
    form->addRow(m_fileStatus);

    outer->addLayout(form);
    outer->addStretch(1);
    return tab;
}

QWidget *MainWindow::buildVerifyTab()
{
    auto *tab = new QWidget;
    auto *outer = new QVBoxLayout(tab);
    outer->setContentsMargins(16, 16, 16, 16);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    {
        auto *row = new QHBoxLayout;
        m_verifyP7m = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseVerifyP7m);
        row->addWidget(m_verifyP7m, 1);
        row->addWidget(b);
        form->addRow(tr("File .p7m da verificare:"), row);
    }
    {
        auto *row = new QHBoxLayout;
        m_verifyTsl = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseVerifyTsl);
        row->addWidget(m_verifyTsl, 1);
        row->addWidget(b);
        form->addRow(tr("TSL di fiducia (opzionale):"), row);
    }

    {
        auto *row = new QHBoxLayout;
        m_verifyBtn = new QPushButton(tr("Verifica firma"));
        connect(m_verifyBtn, &QPushButton::clicked, this, &MainWindow::verifyP7m);
        m_saveOriginalBtn = new QPushButton(tr("Salva file originale (non firmato)"));
        connect(m_saveOriginalBtn, &QPushButton::clicked, this,
                &MainWindow::saveOriginalFile);
        m_saveOriginalBtn->setEnabled(false);
        row->addWidget(m_verifyBtn);
        row->addStretch(1);
        row->addWidget(m_saveOriginalBtn);
        form->addRow(row);
    }

    outer->addLayout(form);

    m_verifyReport = new QPlainTextEdit;
    m_verifyReport->setReadOnly(true);
    m_verifyReport->setPlaceholderText(
        tr("Il report di verifica apparirà qui."));
    outer->addWidget(m_verifyReport, 1);

    m_verifyStatus = new QLabel;
    m_verifyStatus->setWordWrap(true);
    outer->addWidget(m_verifyStatus);
    return tab;
}

QString MainWindow::defaultP11Lib() const
{
    const QStringList candidates = {
        QString::fromLocal8Bit(qgetenv("FDO_PKCS11_LIB")),
        // Bundled with the installed package (Debian): <libdir>/firmadigitaleopen/
        "/usr/lib/x86_64-linux-gnu/firmadigitaleopen/libbit4xpki.so",
        "/usr/lib/firmadigitaleopen/libbit4xpki.so",
        "/usr/lib64/firmadigitaleopen/libbit4xpki.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "../libbit4xpki.so",
        "libbit4xpki.so",
    };
    for (const QString &c : candidates)
        if (!c.isEmpty() && QFileInfo::exists(c))
            return c;
    return "../libbit4xpki.so";
}

void MainWindow::detectSlots(QLineEdit *libEdit, QComboBox *slotBox,
                             std::vector<fdo::Pkcs11Slot> &store)
{
    const QString lib = libEdit->text().trimmed();
    slotBox->blockSignals(true);
    slotBox->clear();
    store.clear();
    slotBox->addItem(lib.isEmpty() ? tr("(nessun modulo)")
                                   : tr("rilevamento token in corso..."));
    slotBox->blockSignals(false);

    if (lib.isEmpty())
        return;

    // Drop any in-flight query for this combo, then ask the worker thread
    // (debounced, so typing a path does not flood the token) to enumerate.
    for (auto it = m_pendingSlots.begin(); it != m_pendingSlots.end();)
        it = (it->box == slotBox) ? m_pendingSlots.erase(it) : std::next(it);
    m_pendingSlots.push_back({ ++m_slotGen, lib, slotBox, &store });
    m_slotDebounce->start();
}

void MainWindow::applySlotResults(QComboBox *box, std::vector<fdo::Pkcs11Slot> &store,
                                  const std::vector<fdo::Pkcs11Slot> &found,
                                  const std::string &err)
{
    box->blockSignals(true);
    box->clear();
    store.clear();
    for (const auto &s : found) {
        QString label = s.tokenLabel.empty()
                            ? tr("slot 0x%1").arg(QString::number(s.index, 16))
                            : QString::fromStdString(s.tokenLabel).trimmed();
        if (!s.certSubject.empty())
            label += " - " + QString::fromStdString(s.certSubject);
        box->addItem(label);
        store.push_back(s);
    }

    if (found.empty()) {
        box->addItem(tr("nessun token") +
                     (err.empty() ? QString()
                                  : " (" + QString::fromStdString(err) + ")"));
    } else {
        for (size_t i = 0; i < found.size(); ++i)
            if (found[i].hasCert) {
                box->setCurrentIndex(int(i));
                break;
            }
    }
    box->blockSignals(false);
}

void MainWindow::issuePendingSlotQueries()
{
    // One worker request per distinct module; combos sharing the same lib
    // piggyback on the same result.
    std::map<QString, int> issued;
    for (auto &q : m_pendingSlots) {
        auto it = issued.find(q.lib);
        if (it != issued.end()) {
            q.gen = it->second;
            continue;
        }
        issued.emplace(q.lib, q.gen);
        emit p11EnumerateRequested(q.lib, q.gen);
    }
}

void MainWindow::onSlotsEnumerated(int gen, const std::vector<fdo::Pkcs11Slot> &found,
                                   const QString &error)
{
    auto it = m_pendingSlots.begin();
    while (it != m_pendingSlots.end()) {
        if (it->gen == gen) {
            applySlotResults(it->box, *it->store, found, error.toStdString());
            it = m_pendingSlots.erase(it);
        } else {
            ++it;
        }
    }
}

void MainWindow::showProgress(const QString &text)
{
    if (m_progress)
        return;
    m_progress = new QProgressDialog(text, nullptr, 0, 0, this);
    m_progress->setWindowModality(Qt::ApplicationModal);
    m_progress->setMinimumDuration(0);
    m_progress->show();
}

void MainWindow::hideProgress()
{
    if (!m_progress)
        return;
    m_progress->hide();
    m_progress->deleteLater();
    m_progress = nullptr;
}

fdo::Pkcs11Slot MainWindow::selectedSlot(QComboBox *box,
                                         const std::vector<fdo::Pkcs11Slot> &store) const
{
    const int i = box->currentIndex();
    if (i >= 0 && i < static_cast<int>(store.size()))
        return store[i];
    for (const auto &s : store)
        if (s.hasCert)
            return s;
    if (!store.empty())
        return store.front();
    return {};
}

void MainWindow::browsePdfInput()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Seleziona PDF"), QString(), tr("PDF files (*.pdf);;Tutti (*.*)"));
    if (path.isEmpty())
        return;
    m_pdfInput->setText(path);
    const QString base = QFileInfo(path).completeBaseName();
    m_pdfOutput->setText(base + "_signed.pdf");
    QString err;
    if (m_preview->loadPdf(path, m_page->value(), &err))
        m_pdfStatus->setText(tr("PDF caricato: %1 pagine").arg(m_preview->pageCount()));
    else
        m_pdfStatus->setText(tr("Errore anteprima: %1").arg(err));
}

void MainWindow::browsePdfOutput()
{
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva PDF firmato"), m_pdfOutput->text(),
        tr("PDF files (*.pdf);;Tutti (*.*)"));
    if (!path.isEmpty())
        m_pdfOutput->setText(path);
}

void MainWindow::browseFileInput()
{
    const QString path =
        QFileDialog::getOpenFileName(this, tr("Seleziona file"), QString());
    if (path.isEmpty())
        return;
    m_fileInput->setText(path);
    m_fileOutput->setText(QFileInfo(path).fileName() + ".p7m");
}

void MainWindow::browseFileOutput()
{
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva .p7m"), m_fileOutput->text(),
        tr("P7M files (*.p7m);;Tutti (*.*)"));
    if (!path.isEmpty())
        m_fileOutput->setText(path);
}

void MainWindow::browseP11Lib()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Modulo PKCS#11"), QString(),
        tr("Shared libs (*.so *.dll *.dylib);;Tutti (*.*)"));
    if (path.isEmpty())
        return;
    m_p11Lib->setText(path);
    m_p7mLib->setText(path);
}

void MainWindow::signPdf()
{
    const QString in = m_pdfInput->text().trimmed();
    const QString out = m_pdfOutput->text().trimmed();
    const QString lib = m_p11Lib->text().trimmed();
    const QString pin = m_p11Pin->text();

    if (in.isEmpty() || !QFileInfo::exists(in)) {
        QMessageBox::warning(this, tr("Ingresso mancante"),
                             tr("Seleziona un PDF di input esistente."));
        return;
    }
    if (out.isEmpty()) {
        QMessageBox::warning(this, tr("Output mancante"),
                             tr("Scegli un nome file di output."));
        return;
    }
    if (lib.isEmpty()) {
        QMessageBox::warning(this, tr("Modulo mancante"),
                             tr("Specifica il percorso del modulo PKCS#11."));
        return;
    }

    std::string err;
    std::vector<unsigned char> pdfBytes;
    if (!readFileBytes(in, pdfBytes, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }

    Pkcs11Worker::SignParams p;
    p.kind = Pkcs11Worker::SignParams::Pades;
    p.libPath = lib;
    p.slotIndex = selectedSlot(m_p11Slot, m_p11Slots).index;
    p.pin = pin;
    p.pdfData = QByteArray(reinterpret_cast<const char *>(pdfBytes.data()),
                           static_cast<int>(pdfBytes.size()));
    p.page = m_page->value();
    p.visible = m_visible->isChecked() && m_preview->hasBox();
    p.visibleText = m_visibleText->text().toStdString();
    if (p.visible) {
        p.boxX1 = m_preview->boxX1();
        p.boxY1 = m_preview->boxY1();
        p.boxX2 = m_preview->boxX2();
        p.boxY2 = m_preview->boxY2();
    }

    m_pdfStatus->setText(tr("Firma in corso..."));
    showProgress(tr("Firma in corso: attendi il token (inserisci il PIN "
                    "sul token se richiesto)..."));
    emit p11SignRequested(p);
}

void MainWindow::signFile()
{
    const QString in = m_fileInput->text().trimmed();
    const QString out = m_fileOutput->text().trimmed();
    const QString lib = m_p7mLib->text().trimmed();
    const QString pin = m_p7mPin->text();

    if (in.isEmpty() || !QFileInfo::exists(in)) {
        QMessageBox::warning(this, tr("Ingresso mancante"),
                             tr("Seleziona un file di input esistente."));
        return;
    }
    if (out.isEmpty()) {
        QMessageBox::warning(this, tr("Output mancante"),
                             tr("Scegli un nome file di output."));
        return;
    }
    if (lib.isEmpty()) {
        QMessageBox::warning(this, tr("Modulo mancante"),
                             tr("Specifica il percorso del modulo PKCS#11."));
        return;
    }

    Pkcs11Worker::SignParams p;
    p.kind = Pkcs11Worker::SignParams::P7M;
    p.libPath = lib;
    p.slotIndex = selectedSlot(m_p7mSlot, m_p7mSlots).index;
    p.pin = pin;
    p.p7mIn = in;
    p.p7mOut = out;

    m_fileStatus->setText(tr("Firma in corso..."));
    showProgress(tr("Firma in corso: attendi il token (inserisci il PIN "
                    "sul token se richiesto)..."));
    emit p11SignRequested(p);
}

void MainWindow::onSignFinished(int kind, bool ok, const QString &error,
                                const QByteArray &pdfOut)
{
    hideProgress();

    if (kind == Pkcs11Worker::SignParams::Pades) {
        const QString out = m_pdfOutput->text().trimmed();
        if (!ok) {
            m_pdfStatus->setText(tr("Firma fallita."));
            QMessageBox::critical(this, tr("Firma fallita"), error);
            return;
        }
        std::vector<unsigned char> pdfBytes(pdfOut.constData(),
                                            pdfOut.constData() + pdfOut.size());
        std::string err;
        if (!writeFileBytes(out, pdfBytes, err)) {
            QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
            return;
        }
        m_pdfStatus->setText(tr("PDF firmato: %1").arg(out));
        QMessageBox::information(this, tr("Completato"),
                                 tr("PDF firmato e salvato in:\n%1").arg(out));
    } else {
        const QString out = m_fileOutput->text().trimmed();
        if (!ok) {
            m_fileStatus->setText(tr("Firma fallita."));
            QMessageBox::critical(this, tr("Firma fallita"), error);
            return;
        }
        m_fileStatus->setText(tr("File firmato: %1").arg(out));
        QMessageBox::information(this, tr("Completato"),
                                 tr("File firmato e salvato in:\n%1").arg(out));
    }
}

void MainWindow::browseVerifyP7m()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Seleziona file .p7m"), QString(),
        tr("P7M files (*.p7m);;Tutti (*.*)"));
    if (path.isEmpty())
        return;
    m_verifyP7m->setText(path);
    verifyP7m();
}

void MainWindow::browseVerifyTsl()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Seleziona TSL (XML)"), QString(),
        tr("TSL XML (*.xml);;Tutti (*.*)"));
    if (!path.isEmpty())
        m_verifyTsl->setText(path);
}

void MainWindow::verifyP7m()
{
    const QString p7mPath = m_verifyP7m->text().trimmed();
    const QString tslPath = m_verifyTsl->text().trimmed();

    if (p7mPath.isEmpty() || !QFileInfo::exists(p7mPath)) {
        QMessageBox::warning(this, tr("Ingresso mancante"),
                             tr("Seleziona un file .p7m esistente."));
        return;
    }

    std::string err;
    std::vector<unsigned char> bytes;
    if (!readFileBytes(p7mPath, bytes, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }

    // Trust anchors: the certificates listed in the TSL (when provided).
    std::vector<const fdo::X509Cert *> anchors;
    std::vector<std::unique_ptr<fdo::X509Cert>> anchorCerts;
    bool tslUsed = false;
    if (!tslPath.isEmpty()) {
        if (!QFileInfo::exists(tslPath)) {
            QMessageBox::warning(this, tr("TSL mancante"),
                                 tr("Il file TSL indicato non esiste."));
            return;
        }
        auto tsl = fdo::TslParser::parseFile(tslPath.toStdString());
        if (!tsl) {
            QMessageBox::critical(this, tr("Errore TSL"),
                                  tr("Impossibile analizzare il file TSL."));
            return;
        }
        for (const auto &der : tsl->allCerts) {
            auto c = fdo::X509Cert::fromDer(der);
            if (c) {
                anchorCerts.push_back(std::move(c));
                anchors.push_back(anchorCerts.back().get());
            }
        }
        if (anchors.empty()) {
            QMessageBox::warning(this, tr("TSL vuota"),
                                 tr("Nessun certificato trovato nella TSL."));
            return;
        }
        tslUsed = true;
    }

    m_verifyStatus->setText(tr("Verifica in corso..."));
    QApplication::setOverrideCursor(Qt::WaitCursor);
    fdo::P7MResult res = fdo::P7M::decodeAndVerify(bytes, anchors);
    bool selfAnchored = false;
    if (!res.ok && !tslUsed && !res.signerCertDer.empty()) {
        // No TSL given: retry with the embedded signer certificate as its own
        // anchor. The RSA signature and content digest are still fully
        // checked; only the trust chain is not evaluated.
        auto signer = fdo::X509Cert::fromDer(res.signerCertDer);
        if (signer) {
            const std::vector<const fdo::X509Cert *> selfAnchors{ signer.get() };
            const fdo::P7MResult r2 = fdo::P7M::decodeAndVerify(bytes, selfAnchors);
            if (r2.ok) {
                res = r2;
                selfAnchored = true;
            }
        }
    }
    QApplication::restoreOverrideCursor();

    QString report;
    if (res.ok) {
        report += tr("=== FIRMA VALIDA ===\n\n");
        if (selfAnchored) {
            report += tr("Nota: nessun TSL caricato; verificata con il certificato "
                         "del firmatario come ancora di fiducia propria (integrità "
                         "e autenticità OK, catena di fiducia non valutata).\n\n");
        }
        report += tr("Firmatario: %1\n").arg(QString::fromStdString(res.signerSubject));
        report += tr("Emittente: %1\n").arg(QString::fromStdString(res.signerIssuer));
        report += tr("Seriale: %1\n").arg(QString::fromStdString(res.signerSerial));
        if (!res.signingTime.empty())
            report += tr("Ora di firma: %1\n").arg(QString::fromStdString(res.signingTime));
        report += tr("Ancora di fiducia: %1\n").arg(QString::fromStdString(res.anchorSubject));
        report += tr("Certificati incorporati: %1\n").arg(res.embeddedCerts);
        if (res.validAtSigningTimeOnly)
            report += tr("Avvertenza: la catena era valida al momento della firma, "
                         "ma non lo è più oggi.\n");
    } else {
        report += tr("=== FIRMA NON VALIDA ===\n\n");
        report += QString::fromStdString(res.error) + "\n";
        if (!res.signerSubject.empty()) {
            report += "\n" + tr("Firmatario: %1\n")
                          .arg(QString::fromStdString(res.signerSubject));
            if (!res.signingTime.empty())
                report += tr("Ora di firma: %1\n")
                              .arg(QString::fromStdString(res.signingTime));
        }
    }
    if (!res.content.empty())
        report += "\n" + tr("File originale incorporato: %1 byte\n").arg(res.content.size());
    m_verifyReport->setPlainText(report);

    m_verifyContent = res.ok ? res.content : std::vector<unsigned char>();
    m_verifyContentReady = res.ok && !res.content.empty();
    m_saveOriginalBtn->setEnabled(m_verifyContentReady);

    m_verifyStatus->setText(res.ok
                                ? (selfAnchored ? tr("Firma valida (ancora propria, nessun TSL).")
                                                : tr("Firma valida."))
                                : tr("Firma non valida."));
}

void MainWindow::saveOriginalFile()
{
    if (!m_verifyContentReady) {
        QMessageBox::information(
            this, tr("Non disponibile"),
            tr("Esegui prima una verifica di successo: il file originale è "
               "disponibile solo se la firma è valida."));
        return;
    }
    QString suggested = QFileInfo(m_verifyP7m->text()).fileName();
    if (suggested.endsWith(".p7m", Qt::CaseInsensitive))
        suggested.chop(5);
    if (suggested.isEmpty())
        suggested = "originale.bin";
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva file originale (non firmato)"), suggested, tr("Tutti (*.*)"));
    if (path.isEmpty())
        return;
    std::string err;
    if (!writeFileBytes(path, m_verifyContent, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }
    m_verifyStatus->setText(tr("File originale salvato: %1").arg(path));
}

void MainWindow::openFileForVerify(const QString &path)
{
    m_tabs->setCurrentIndex(2);
    m_verifyP7m->setText(path);
    verifyP7m();
}

QString MainWindow::verifyReportText() const
{
    return m_verifyReport ? m_verifyReport->toPlainText() : QString();
}
