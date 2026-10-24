#include "mainwindow.h"
#include "pdfpreview.h"
#include "pades.h"
#include "p7m.h"
#include "x509util.h"

#include <QStringList>
#include <QTabWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QFile>
#include <QFont>
#include <QApplication>
#include <QFrame>
#include <QThread>
#include <QTimer>
#include <QProgressDialog>
#include <QMetaType>
#include <QUrl>
#include <QDir>
#include <QStandardPaths>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSettings>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

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

// Official Italian TSL from the AgID eIDAS Digital Service list.
const char kTslUrl[] = "https://eidas.agid.gov.it/TL/TSL-IT.xml";

QString lastUsedDir()
{
    return QSettings().value(QStringLiteral("lastDir")).toString();
}

void recordUsedDir(const QString &path)
{
    if (path.isEmpty())
        return;
    QSettings s;
    s.setValue(QStringLiteral("lastDir"), QFileInfo(path).absolutePath());
}

QString cnFromSubject(const std::string &subject)
{
    const std::string key = "CN=";
    std::string::size_type pos = subject.find(key);
    if (pos == std::string::npos)
        return QString();
    pos += key.size();
    std::string::size_type end = subject.find(',', pos);
    if (end == std::string::npos)
        end = subject.size();
    return QString::fromStdString(subject.substr(pos, end - pos)).trimmed();
}

// ---------------------------------------------------------------------------
// Rich-text blocks for the verification report (QTextEdit HTML subset).
// Fixed light backgrounds keep the banners readable on light and dark themes.
// ---------------------------------------------------------------------------
QString reportBanner(const QString &title, const QString &subtitle,
                     const QString &background, const QString &bar,
                     const QString &foreground)
{
    QString sub;
    if (!subtitle.isEmpty())
        sub = QStringLiteral("<br><span style=\"font-size:10pt;\">%1</span>")
                  .arg(subtitle.toHtmlEscaped());
    return QStringLiteral(
               "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" "
               "style=\"margin-bottom:10px;\"><tr>"
               "<td width=\"8\" bgcolor=\"%1\">&nbsp;</td>"
               "<td bgcolor=\"%2\" style=\"padding:10px 14px;\">"
               "<span style=\"font-size:18pt; font-weight:700; color:%3;\">%4</span>%5"
               "</td></tr></table>")
        .arg(bar, background, foreground, title.toHtmlEscaped(), sub);
}

QString reportRow(const QString &label, const QString &value)
{
    return QStringLiteral(
               "<tr>"
               "<td valign=\"top\" style=\"padding:4px 16px 4px 0; color:#64748b;\">"
               "<b>%1</b></td>"
               "<td valign=\"top\" style=\"padding:4px 0;\">%2</td>"
               "</tr>")
        .arg(label.toHtmlEscaped(), value.toHtmlEscaped());
}

QString reportNotice(const QString &text, const QString &background,
                     const QString &border, const QString &foreground)
{
    return QStringLiteral(
               "<table width=\"100%\" cellspacing=\"0\" cellpadding=\"8\" "
               "style=\"margin-top:8px;\"><tr>"
               "<td width=\"8\" bgcolor=\"%1\">&nbsp;</td>"
               "<td bgcolor=\"%2\"><span style=\"color:%3; font-weight:700;\">"
               "%4</span></td></tr></table>")
        .arg(border, background, foreground, text.toHtmlEscaped());
}

QString reportFooter(const QString &text)
{
    return QStringLiteral(
               "<p style=\"margin-top:14px; color:#64748b; font-size:9pt;\">"
               "%1</p>")
        .arg(text.toHtmlEscaped());
}

QString stampSignerName(const fdo::Pkcs11Slot &slot)
{
    const QString gn = QString::fromStdString(slot.certGivenName).trimmed();
    const QString sn = QString::fromStdString(slot.certSurname).trimmed();
    if (!gn.isEmpty() || !sn.isEmpty()) {
        if (gn.isEmpty())
            return sn;
        if (sn.isEmpty())
            return gn;
        return gn + " " + sn;
    }
    return cnFromSubject(slot.certSubject);
}

} // namespace

struct MainWindow::TslResolution {
    enum class State { Ok, NoTsl };
    State state = State::NoTsl;
    QString path;   // TSL file actually used (cache, download or explicit select)
    QString info;   // human-readable TSL identity shown in the verification report
    QString error;  // reason when state != Ok
    std::vector<std::unique_ptr<fdo::X509Cert>> certs;
    std::vector<const fdo::X509Cert *> anchors;
};

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
    setAcceptDrops(true);

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
    connect(m_p11Slot, qOverload<int>(&QComboBox::currentIndexChanged), this,
            [this](int) { updateCertInfo(m_p11Slot, m_p11Slots, m_p11CertInfo); });
    connect(m_p7mSlot, qOverload<int>(&QComboBox::currentIndexChanged), this,
            [this](int) { updateCertInfo(m_p7mSlot, m_p7mSlots, m_p7mCertInfo); });
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

    m_p11CertInfo = new QLabel;
    m_p11CertInfo->setWordWrap(true);
    m_p11CertInfo->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_p11CertInfo->hide();
    lv->addWidget(m_p11CertInfo);

    lv->addWidget(new QLabel(tr("PIN:")));
    m_p11Pin = new QLineEdit;
    m_p11Pin->setEchoMode(QLineEdit::Password);
    lv->addWidget(m_p11Pin);

    auto *line = new QFrame;
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    lv->addWidget(line);

    m_visible = new QCheckBox(tr("Firma visibile (clicca sul documento per posizionarla)"));
    m_visible->setChecked(true);
    lv->addWidget(m_visible);

    lv->addWidget(new QLabel(tr("Prefisso firma:")));
    m_visibleText = new QLineEdit("Firmato digitalmente da ");
    lv->addWidget(m_visibleText);

    lv->addWidget(new QLabel(tr("Dimensione testo firma (pt):")));
    m_stampFont = new QSpinBox;
    m_stampFont->setRange(6, 72);
    m_stampFont->setSuffix(tr(" pt"));
    m_stampFont->setValue(QSettings().value(QStringLiteral("stampFont"), 12).toInt());
    connect(m_stampFont, qOverload<int>(&QSpinBox::valueChanged), this,
            [this](int v) {
                QSettings().setValue(QStringLiteral("stampFont"), v);
                if (m_preview)
                    m_preview->setStampFont(double(v));
            });
    lv->addWidget(m_stampFont);

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
    m_preview->setStampFont(double(m_stampFont->value()));
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
    connect(m_visibleText, &QLineEdit::textChanged, this,
            [this](const QString &text) {
                m_preview->setStampInfo(
                    text, stampSignerName(selectedSlot(m_p11Slot, m_p11Slots)));
            });
    m_preview->setStampInfo(m_visibleText->text(),
                            stampSignerName(selectedSlot(m_p11Slot, m_p11Slots)));

    m_boxLabel = new QLabel(tr("Clicca sul documento per posizionare la firma visibile"));

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

    m_p7mCertInfo = new QLabel;
    m_p7mCertInfo->setWordWrap(true);
    m_p7mCertInfo->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_p7mCertInfo->hide();
    form->addRow(m_p7mCertInfo);

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
        form->addRow(tr("File firmato da verificare (.pdf / .p7m):"), row);
    }
    {
        auto *row = new QHBoxLayout;
        m_verifyTsl = new QLineEdit;
        auto *b = new QPushButton(tr("Sfoglia..."));
        connect(b, &QPushButton::clicked, this, &MainWindow::browseVerifyTsl);
        m_tslRefreshBtn = new QPushButton(tr("Aggiorna TSL"));
        connect(m_tslRefreshBtn, &QPushButton::clicked, this, &MainWindow::refreshTsl);
        row->addWidget(m_verifyTsl, 1);
        row->addWidget(b);
        row->addWidget(m_tslRefreshBtn);
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

    m_verifyStatus = new QLabel;
    m_verifyStatus->setWordWrap(true);
    m_verifyStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_verifyStatus->hide();
    outer->addWidget(m_verifyStatus);

    auto *reportTitle = new QLabel(tr("Report di verifica"));
    QFont reportFont = reportTitle->font();
    reportFont.setBold(true);
    reportTitle->setFont(reportFont);
    outer->addWidget(reportTitle);

    m_verifyReport = new QTextEdit;
    m_verifyReport->setReadOnly(true);
    m_verifyReport->setAcceptRichText(true);
    m_verifyReport->setPlaceholderText(
        tr("Il report di verifica apparirà qui."));
    outer->addWidget(m_verifyReport, 1);
    return tab;
}

QString MainWindow::defaultP11Lib() const
{
#ifdef Q_OS_WIN
    const QString appDir = QCoreApplication::applicationDirPath();
    const QString winDir = QString::fromLocal8Bit(qgetenv("SystemRoot"));
    const QString pf86 = QString::fromLocal8Bit(qgetenv("ProgramFiles(x86)"));
    const QString pf = QString::fromLocal8Bit(qgetenv("ProgramFiles"));
    const QStringList candidates = {
        QString::fromLocal8Bit(qgetenv("FDO_PKCS11_LIB")),
        // Explicit per-installation override next to the executable.
        appDir + "/libbit4xpki.dll",
        // Prefer a machine-wide Bit4id middleware install when present: it
        // ships its full x64 companion set and registry configuration.
        winDir + "/System32/bit4xpki.dll",
        pf86 + "/Bit4Id/Universal MW/etc/bit4xpki.dll",
        pf + "/Bit4Id/Universal MW/etc/bit4xpki.dll",
        // Self-contained bundle shipped by the installer.
        appDir + "/bit4xpki.dll",
        winDir + "/System32/libbit4xpki.dll",
        // OpenSC is handy for testing with non-Bit4id tokens.
        winDir + "/System32/opensc-pkcs11.dll",
        // Bare names: LoadLibraryW also searches PATH and the app directory.
        "bit4xpki.dll",
        "libbit4xpki.dll",
    };
    for (const QString &c : candidates)
        if (!c.isEmpty() && QFileInfo::exists(c))
            return c;
    return appDir + "/bit4xpki.dll";
#else
    const QStringList candidates = {
        QString::fromLocal8Bit(qgetenv("FDO_PKCS11_LIB")),
        // AppImage: the module bundle lives inside the mounted AppDir
        // (triple is multiarch: <libdir>/firmadigitaleopen/).
        QString::fromLocal8Bit(qgetenv("APPDIR")) + "/usr/lib/x86_64-linux-gnu/firmadigitaleopen/libbit4xpki.so",
        QString::fromLocal8Bit(qgetenv("APPDIR")) + "/usr/lib/firmadigitaleopen/libbit4xpki.so",
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
#endif
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
    updateCertInfo(m_p11Slot, m_p11Slots, m_p11CertInfo);
    updateCertInfo(m_p7mSlot, m_p7mSlots, m_p7mCertInfo);
    if (m_preview) {
        m_preview->setStampInfo(
            m_visibleText->text(),
            stampSignerName(selectedSlot(m_p11Slot, m_p11Slots)));
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

void MainWindow::updateCertInfo(QComboBox *box,
                                const std::vector<fdo::Pkcs11Slot> &store,
                                QLabel *label)
{
    if (!label)
        return;
    const int i = box->currentIndex();
    if (i < 0 || i >= static_cast<int>(store.size()) || !store[i].hasCert) {
        label->hide();
        return;
    }
    const fdo::Pkcs11Slot &s = store[i];
    const QString id = s.certKeyId.empty()
                           ? tr("non disponibile")
                           : QString::fromStdString(s.certKeyId);
    QStringList lines;
    lines << tr("Certificato: %1").arg(QString::fromStdString(s.certSubject));
    lines << tr("CKA_ID: %1").arg(id);
    lines << (s.certNotAfter.empty()
                  ? tr("Scadenza: non disponibile")
                  : tr("Scadenza: %1").arg(QString::fromStdString(s.certNotAfter)));

    bool warn = false;
    if (s.certExpired) {
        lines << tr("ATTENZIONE: certificato SCADUTO.");
        warn = true;
    }
    if (!s.certKeyIdIsDs) {
        lines << tr("ATTENZIONE: CKA_ID non DSx (atteso DS3, DS4, DS5...).");
        warn = true;
    }

    label->setText(lines.join("\n"));
    if (s.certExpired) {
        label->setStyleSheet(
            "QLabel { background-color:#fee2e2; color:#7f1d1d; "
            "border:1px solid #dc2626; border-radius:6px; padding:6px 8px; "
            "font-weight:700; }");
    } else if (warn) {
        label->setStyleSheet(
            "QLabel { background-color:#fef3c7; color:#78350f; "
            "border:1px solid #f59e0b; border-radius:6px; padding:6px 8px; "
            "font-weight:700; }");
    } else {
        label->setStyleSheet(
            "QLabel { background-color:#dcfce7; color:#14532d; "
            "border:1px solid #16a34a; border-radius:6px; padding:6px 8px; }");
    }
    label->show();
}

bool MainWindow::confirmSlotWarnings(const fdo::Pkcs11Slot &slot)
{
    if (!slot.hasCert)
        return true;
    QStringList warnings;
    if (slot.certExpired) {
        warnings << tr("Il certificato è SCADUTO il %1.")
                        .arg(slot.certNotAfter.empty()
                                 ? tr("(data non disponibile)")
                                 : QString::fromStdString(slot.certNotAfter));
    }
    if (!slot.certKeyIdIsDs) {
        warnings << tr("Il certificato non ha un CKA_ID DSx (trovato: %1).")
                        .arg(slot.certKeyId.empty()
                                 ? tr("non disponibile")
                                 : QString::fromStdString(slot.certKeyId));
    }
    if (warnings.isEmpty())
        return true;
    const auto answer = QMessageBox::warning(
        this, tr("Attenzione certificato"),
        warnings.join("\n\n") + "\n\n" +
            tr("Continuare comunque con la firma?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    return answer == QMessageBox::Yes;
}

void MainWindow::loadFileInput(const QString &path)
{
    m_pdfInput->setText(path);
    const QFileInfo fi(path);
    m_pdfOutput->setText(
        fi.absolutePath() + "/" + fi.completeBaseName() + "_signed.pdf");
    recordUsedDir(path);
    QString err;
    if (m_preview->loadPdf(path, m_page->value(), &err))
        m_pdfStatus->setText(tr("PDF caricato: %1 pagine").arg(m_preview->pageCount()));
    else
        m_pdfStatus->setText(tr("Errore anteprima: %1").arg(err));
}

void MainWindow::browsePdfInput()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Seleziona PDF"), lastUsedDir(),
        tr("PDF files (*.pdf);;Tutti (*.*)"));
    if (path.isEmpty())
        return;
    loadFileInput(path);
}

void MainWindow::browsePdfOutput()
{
    const QString start = m_pdfOutput->text().isEmpty()
                              ? lastUsedDir()
                              : m_pdfOutput->text();
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva PDF firmato"), start,
        tr("PDF files (*.pdf);;Tutti (*.*)"));
    if (!path.isEmpty()) {
        m_pdfOutput->setText(path);
        recordUsedDir(path);
    }
}

void MainWindow::browseFileInput()
{
    const QString path =
        QFileDialog::getOpenFileName(this, tr("Seleziona file"), lastUsedDir());
    if (path.isEmpty())
        return;
    m_fileInput->setText(path);
    const QFileInfo fi(path);
    m_fileOutput->setText(fi.absolutePath() + "/" + fi.fileName() + ".p7m");
    recordUsedDir(path);
}

void MainWindow::browseFileOutput()
{
    const QString start = m_fileOutput->text().isEmpty()
                              ? lastUsedDir()
                              : m_fileOutput->text();
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva .p7m"), start,
        tr("P7M files (*.p7m);;Tutti (*.*)"));
    if (!path.isEmpty()) {
        m_fileOutput->setText(path);
        recordUsedDir(path);
    }
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

    const fdo::Pkcs11Slot slot = selectedSlot(m_p11Slot, m_p11Slots);
    if (!confirmSlotWarnings(slot))
        return;

    std::string err;
    std::vector<unsigned char> pdfBytes;
    if (!readFileBytes(in, pdfBytes, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }

    Pkcs11Worker::SignParams p;
    p.kind = Pkcs11Worker::SignParams::Pades;
    p.libPath = lib;
    p.slotIndex = slot.index;
    p.pin = pin;
    p.pdfData = QByteArray(reinterpret_cast<const char *>(pdfBytes.data()),
                           static_cast<int>(pdfBytes.size()));
    p.page = m_page->value();
    p.visible = m_visible->isChecked();
    p.visibleText = m_visibleText->text().toStdString();
    p.stampMaxFont = double(m_stampFont->value());
    if (p.visible) {
        if (m_preview->hasBox()) {
            p.boxX1 = m_preview->boxX1();
            p.boxY1 = m_preview->boxY1();
            p.boxX2 = m_preview->boxX2();
            p.boxY2 = m_preview->boxY2();
        } else {
            const QSizeF ps = m_preview->pageSize();
            if (ps.width() > 24.0 && ps.height() > 24.0) {
                const std::string name =
                    stampSignerName(selectedSlot(m_p11Slot, m_p11Slots))
                        .toStdString();
                const std::string line1 = p.visibleText + " : " + name;
                const std::string line2 =
                    "Time: " + fdo::stampTimeString(std::time(nullptr));
                const fdo::StampBox fit =
                    fdo::stampFitBox(line1, line2, p.stampMaxFont);
                const double w = std::min(fit.w, ps.width() - 24.0);
                const double h = std::min(fit.h, ps.height() - 24.0);
                p.boxX2 = ps.width() - 24.0;
                p.boxX1 = p.boxX2 - w;
                p.boxY2 = ps.height() - 24.0;
                p.boxY1 = p.boxY2 - h;
            } else {
                p.boxX1 = 50.0;
                p.boxY1 = 50.0;
                p.boxX2 = 250.0;
                p.boxY2 = 100.0;
            }
            m_boxLabel->setText(tr("Nessuna posizione scelta: firma in alto a "
                                   "destra (clicca sul documento per "
                                   "posizionarla)"));
        }
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

    const fdo::Pkcs11Slot slot = selectedSlot(m_p7mSlot, m_p7mSlots);
    if (!confirmSlotWarnings(slot))
        return;

    Pkcs11Worker::SignParams p;
    p.kind = Pkcs11Worker::SignParams::P7M;
    p.libPath = lib;
    p.slotIndex = slot.index;
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

    if (kind == Pkcs11Worker::SignParams::Pades)
        m_p11Pin->clear();
    else
        m_p7mPin->clear();

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
        this, tr("Seleziona un file firmato"), lastUsedDir(),
        tr("File firmati (*.pdf *.p7m);;PDF (*.pdf);;P7M (*.p7m);;Tutti (*.*)"));
    if (path.isEmpty())
        return;
    m_verifyP7m->setText(path);
    recordUsedDir(path);
    verifyP7m();
}

void MainWindow::browseVerifyTsl()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Seleziona TSL (XML)"), lastUsedDir(),
        tr("TSL XML (*.xml);;Tutti (*.*)"));
    if (!path.isEmpty()) {
        m_verifyTsl->setText(path);
        recordUsedDir(path);
    }
}

QString MainWindow::cachedTslPath() const
{
    QString dir = QString::fromLocal8Bit(qgetenv("FDO_TSL_CACHE_DIR"));
    if (dir.isEmpty())
        dir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(dir);
    return dir + "/TSL-IT.xml";
}

bool MainWindow::downloadTsl(const QUrl &url, QByteArray &out, QString &err) const
{
    QNetworkAccessManager nam;
    QNetworkRequest req(url);
    req.setTransferTimeout(15000);
    req.setRawHeader("User-Agent", QByteArrayLiteral("FirmaDigitaleOpen"));
    QNetworkReply *reply = nam.get(req);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    const bool ok = reply->error() == QNetworkReply::NoError;
    if (ok)
        out = reply->readAll();
    else
        err = reply->errorString();
    reply->deleteLater();
    return ok && !out.isEmpty();
}

void MainWindow::refreshTsl()
{
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QByteArray data;
    QString derr;
    const bool ok = downloadTsl(QUrl(QString::fromLatin1(kTslUrl)), data, derr);
    QApplication::restoreOverrideCursor();
    if (!ok) {
        QMessageBox::critical(this, tr("Aggiornamento TSL non riuscito"),
                              tr("Impossibile scaricare la TSL:\n%1").arg(derr));
        return;
    }
    const QString cache = cachedTslPath();
    std::string werr;
    const std::vector<unsigned char> bytes(data.constBegin(), data.constEnd());
    if (!writeFileBytes(cache, bytes, werr)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(werr));
        return;
    }
    auto tsl = fdo::TslParser::parseFile(cache.toStdString());
    if (!tsl) {
        QMessageBox::warning(this, tr("TSL non valida"),
                             tr("Il file scaricato non è una TSL analizzabile:\n%1")
                                 .arg(cache));
        return;
    }
    setVerifyStatus(tr("TSL aggiornata: %1 (%2 certificati di fiducia)")
                        .arg(QString::fromStdString(tsl->issueDateTime))
                        .arg(tsl->trustAnchors().size()),
                    VerifyStatus::Info);
}

MainWindow::TslResolution MainWindow::resolveTsl(bool allowDownload)
{
    TslResolution res;
    const QString tslPath = m_verifyTsl->text().trimmed();

    const auto takeCerts = [&res](const fdo::Tsl &tsl) {
        // Only CA certificates of currently valid services listed in the TSL
        // become trust anchors. The document's own certificates and the TSL
        // XML-signature certificate are never used.
        for (const auto &der : tsl.trustAnchors()) {
            auto c = fdo::X509Cert::fromDer(der);
            if (c) {
                res.certs.push_back(std::move(c));
                res.anchors.push_back(res.certs.back().get());
            }
        }
        return !res.anchors.empty();
    };
    const auto infoOf = [](const fdo::Tsl &tsl) {
        return QStringLiteral("TSL del %1 (aggiornamento previsto %2)")
            .arg(QString::fromStdString(tsl.issueDateTime),
                 QString::fromStdString(tsl.nextUpdate));
    };

    if (!tslPath.isEmpty()) {
        if (!QFileInfo::exists(tslPath)) {
            res.error = tr("Il file TSL indicato non esiste: %1").arg(tslPath);
            return res;
        }
        auto tsl = fdo::TslParser::parseFile(tslPath.toStdString());
        if (!tsl) {
            res.error = tr("Impossibile analizzare il file TSL: %1").arg(tslPath);
            return res;
        }
        if (!tsl->upToDate()) {
            res.error = tr("TSL non aggiornata (aggiornamento previsto il %1): %2.\n"
                           "Usa \"Aggiorna TSL\" per scaricare la lista corrente, "
                           "oppure seleziona una versione aggiornata.")
                            .arg(QString::fromStdString(tsl->nextUpdate), tslPath);
            return res;
        }
        if (!takeCerts(*tsl)) {
            res.error = tr("Nessun certificato di fiducia nella TSL: %1").arg(tslPath);
            return res;
        }
        res.path = tslPath;
        res.info = infoOf(*tsl);
        res.state = TslResolution::State::Ok;
        return res;
    }

    const QString cache = cachedTslPath();
    if (QFileInfo::exists(cache)) {
        auto tsl = fdo::TslParser::parseFile(cache.toStdString());
        if (tsl && tsl->upToDate() && takeCerts(*tsl)) {
            res.path = cache;
            res.info = infoOf(*tsl);
            res.state = TslResolution::State::Ok;
            return res;
        }
        res.certs.clear();
        res.anchors.clear();
    }

    if (allowDownload) {
        QApplication::setOverrideCursor(Qt::WaitCursor);
        QByteArray data;
        QString derr;
        const bool ok = downloadTsl(QUrl(QString::fromLatin1(kTslUrl)), data, derr);
        QApplication::restoreOverrideCursor();
        if (ok) {
            std::string werr;
            const std::vector<unsigned char> bytes(data.constBegin(), data.constEnd());
            if (writeFileBytes(cache, bytes, werr)) {
                auto tsl = fdo::TslParser::parseFile(cache.toStdString());
                if (tsl && tsl->upToDate() && takeCerts(*tsl)) {
                    res.path = cache;
                    res.info = infoOf(*tsl);
                    res.state = TslResolution::State::Ok;
                    return res;
                }
                res.certs.clear();
                res.anchors.clear();
            }
        }
        res.error = tr("Nessuna TSL disponibile: impossibile scaricare la lista di "
                       "fiducia (%1). La verifica non può stabilire una catena di "
                       "fiducia senza una TSL aggiornata.")
                        .arg(derr.isEmpty() ? tr("dati non validi") : derr);
        return res;
    }

    res.error = tr("Nessuna TSL disponibile o aggiornata: la verifica non può "
                   "stabilire una catena di fiducia senza una TSL aggiornata.");
    return res;
}

void MainWindow::verifyP7m()
{
    const QString p7mPath = m_verifyP7m->text().trimmed();

    if (p7mPath.isEmpty() || !QFileInfo::exists(p7mPath)) {
        QMessageBox::warning(this, tr("Ingresso mancante"),
                             tr("Seleziona un file firmato (.pdf o .p7m) esistente."));
        return;
    }

    const bool isPdf = p7mPath.endsWith(QLatin1String(".pdf"), Qt::CaseInsensitive);

    std::string err;
    std::vector<unsigned char> bytes;
    if (!readFileBytes(p7mPath, bytes, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }

    // A fresh, usable TSL is mandatory: without it no trust chain can be
    // established and the signature cannot be declared valid. If none was
    // selected or cached, try to download the current Italian list first.
    setVerifyStatus(tr("Verifica in corso..."), VerifyStatus::Busy);
    const bool allowDownload = qEnvironmentVariableIsEmpty("FDO_DISABLE_TSL_DOWNLOAD");
    const TslResolution tslRes = resolveTsl(allowDownload);

    if (tslRes.state != TslResolution::State::Ok) {
        QString html = reportBanner(tr("FIRMA NON VALIDA"),
                                    tr("Nessuna TSL aggiornata disponibile."),
                                    "#fee2e2", "#dc2626", "#7f1d1d");
        html += reportNotice(tslRes.error, "#fef2f2", "#dc2626", "#7f1d1d");
        m_verifyReport->setHtml(html);
        m_verifyContent.clear();
        m_verifyContentReady = false;
        m_saveOriginalBtn->setEnabled(false);
        setVerifyStatus(tr("Firma non valida (nessuna TSL aggiornata)."),
                        VerifyStatus::Error);
        return;
    }

    QApplication::setOverrideCursor(Qt::WaitCursor);
    const fdo::P7MResult res =
        isPdf ? fdo::Pades::verify(bytes, tslRes.anchors)
              : fdo::P7M::decodeAndVerify(bytes, tslRes.anchors);
    QApplication::restoreOverrideCursor();

    const QString typeLabel =
        isPdf ? tr("PDF firmato (PAdES incorporato)") : tr("File P7M (CAdES)");
    QString html;
    if (res.ok) {
        html += reportBanner(tr("FIRMA VALIDA"),
                             tr("La firma è valida e la catena termina su un'ancora "
                                "della TSL."),
                             "#dcfce7", "#16a34a", "#14532d");
        if (res.validAtSigningTimeOnly)
            html += reportNotice(tr("Avvertenza: la catena era valida al momento "
                                    "della firma, ma non lo è più oggi."),
                                 "#fef3c7", "#f59e0b", "#78350f");
        html += QStringLiteral("<table width=\"100%\" cellspacing=\"0\" "
                               "cellpadding=\"0\" style=\"margin-top:8px;\">");
        html += reportRow(tr("Tipo di firma"), typeLabel);
        html += reportRow(tr("Firmatario"),
                          QString::fromStdString(res.signerSubject));
        html += reportRow(tr("Emittente"),
                          QString::fromStdString(res.signerIssuer));
        html += reportRow(tr("Seriale"),
                          QString::fromStdString(res.signerSerial));
        if (!res.signingTime.empty())
            html += reportRow(tr("Ora di firma"),
                              QString::fromStdString(res.signingTime));
        html += reportRow(tr("Ancora di fiducia"),
                          QString::fromStdString(res.anchorSubject));
        html += reportRow(tr("Certificati incorporati"),
                          QString::number(res.embeddedCerts));
        if (!res.content.empty())
            html += reportRow(tr("File originale incorporato"),
                              tr("%1 byte").arg(static_cast<qulonglong>(
                                  res.content.size())));
        html += QStringLiteral("</table>");
    } else {
        html += reportBanner(tr("FIRMA NON VALIDA"),
                             tr("La firma non supera la verifica."),
                             "#fee2e2", "#dc2626", "#7f1d1d");
        html += reportNotice(QString::fromStdString(res.error), "#fef2f2",
                             "#dc2626", "#7f1d1d");
        if (!res.signerSubject.empty() || !res.signingTime.empty()) {
            html += QStringLiteral("<table width=\"100%\" cellspacing=\"0\" "
                                   "cellpadding=\"0\" style=\"margin-top:8px;\">");
            if (!res.signerSubject.empty())
                html += reportRow(tr("Firmatario"),
                                  QString::fromStdString(res.signerSubject));
            if (!res.signingTime.empty())
                html += reportRow(tr("Ora di firma"),
                                  QString::fromStdString(res.signingTime));
            html += QStringLiteral("</table>");
        }
    }
    html += reportFooter(tr("TSL di fiducia: %1").arg(tslRes.info));
    m_verifyReport->setHtml(html);

    m_verifyContent = res.ok ? res.content : std::vector<unsigned char>();
    m_verifyContentReady = res.ok && !res.content.empty();
    m_saveOriginalBtn->setEnabled(m_verifyContentReady);

    if (res.ok) {
        if (res.validAtSigningTimeOnly)
            setVerifyStatus(tr("Firma valida solo al momento della firma."),
                            VerifyStatus::Warning);
        else
            setVerifyStatus(tr("Firma valida."), VerifyStatus::Ok);
    } else {
        setVerifyStatus(tr("Firma non valida."), VerifyStatus::Error);
    }
}

void MainWindow::setVerifyStatus(const QString &text, VerifyStatus status)
{
    QString background, foreground, border;
    switch (status) {
    case VerifyStatus::Ok:
        background = QStringLiteral("#dcfce7");
        foreground = QStringLiteral("#14532d");
        border = QStringLiteral("#16a34a");
        break;
    case VerifyStatus::Warning:
        background = QStringLiteral("#fef3c7");
        foreground = QStringLiteral("#78350f");
        border = QStringLiteral("#f59e0b");
        break;
    case VerifyStatus::Error:
        background = QStringLiteral("#fee2e2");
        foreground = QStringLiteral("#7f1d1d");
        border = QStringLiteral("#dc2626");
        break;
    case VerifyStatus::Busy:
        background = QStringLiteral("#e0f2fe");
        foreground = QStringLiteral("#075985");
        border = QStringLiteral("#0ea5e9");
        break;
    case VerifyStatus::Info:
    default:
        background = QStringLiteral("#e2e8f0");
        foreground = QStringLiteral("#334155");
        border = QStringLiteral("#94a3b8");
        break;
    }
    m_verifyStatus->setStyleSheet(
        QStringLiteral("QLabel { background-color:%1; color:%2; border:1px solid "
                       "%3; border-radius:6px; padding:8px 12px; "
                       "font-weight:700; }")
            .arg(background, foreground, border));
    m_verifyStatus->setText(text);
    m_verifyStatus->setVisible(!text.isEmpty());
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
    QString suggested = lastUsedDir();
    QString name = QFileInfo(m_verifyP7m->text()).completeBaseName();
    if (name.isEmpty())
        name = "originale.bin";
    if (!suggested.isEmpty())
        suggested += "/";
    suggested += name;
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Salva file originale (non firmato)"), suggested, tr("Tutti (*.*)"));
    if (path.isEmpty())
        return;
    recordUsedDir(path);
    std::string err;
    if (!writeFileBytes(path, m_verifyContent, err)) {
        QMessageBox::critical(this, tr("Errore"), QString::fromStdString(err));
        return;
    }
    setVerifyStatus(tr("File originale salvato: %1").arg(path),
                    VerifyStatus::Info);
}

void MainWindow::openFileForVerify(const QString &path)
{
    m_tabs->setCurrentIndex(2);
    m_verifyP7m->setText(path);
    verifyP7m();
}

void MainWindow::openFileForSignPades(const QString &path)
{
    if (!path.endsWith(QLatin1String(".pdf"), Qt::CaseInsensitive)) {
        QMessageBox::warning(
            this, tr("File non PDF"),
            tr("La firma PAdES richiede un file PDF:\n%1").arg(path));
        return;
    }
    m_tabs->setCurrentIndex(0);
    loadFileInput(path);
}

void MainWindow::openFileForSignP7m(const QString &path)
{
    m_tabs->setCurrentIndex(1);
    m_fileInput->setText(path);
    const QFileInfo fi(path);
    m_fileOutput->setText(fi.absolutePath() + "/" + fi.fileName() + ".p7m");
    recordUsedDir(path);
    m_p7mPin->setFocus();
}

void MainWindow::loadVerifyFile(const QString &path)
{
    m_verifyP7m->setText(path);
    verifyP7m();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
    else
        event->ignore();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    const QList<QUrl> urls = event->mimeData()->urls();
    if (urls.isEmpty()) {
        event->ignore();
        return;
    }
    const QString path = urls.first().toLocalFile();
    if (path.isEmpty()) {
        event->ignore();
        return;
    }
    event->acceptProposedAction();
    switch (m_tabs->currentIndex()) {
    case 0: // Firma PDF
        if (path.endsWith(QLatin1String(".pdf"), Qt::CaseInsensitive))
            loadFileInput(path);
        break;
    case 1: { // Firma File (P7M)
        m_fileInput->setText(path);
        const QFileInfo fi(path);
        m_fileOutput->setText(fi.absolutePath() + "/" + fi.fileName() + ".p7m");
        recordUsedDir(path);
        break;
    }
    case 2: // Verifica
        loadVerifyFile(path);
        break;
    default:
        break;
    }
}

QString MainWindow::verifyReportText() const
{
    return m_verifyReport ? m_verifyReport->toPlainText() : QString();
}
