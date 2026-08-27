#pragma once

#include <QByteArray>
#include <QMainWindow>
#include <QString>
#include <vector>

#include "p11worker.h"
#include "pkcs11.h"

class QTabWidget;
class QLineEdit;
class QComboBox;
class QSpinBox;
class QCheckBox;
class QLabel;
class QPushButton;
class QScrollArea;
class QPlainTextEdit;
class QThread;
class QTimer;
class QProgressDialog;

namespace fdo {
class PdfPreview;
struct P7MResult;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    // Switch to the verification tab, load `path` and run the verification.
    // Used when a .p7m file is opened via the file association.
    void openFileForVerify(const QString &path);

    // Plain text of the last verification report (empty before the first run).
    QString verifyReportText() const;

private slots:
    void browsePdfInput();
    void browsePdfOutput();
    void browseFileInput();
    void browseFileOutput();
    void browseP11Lib();
    void signPdf();
    void signFile();
    void browseVerifyP7m();
    void browseVerifyTsl();
    void verifyP7m();
    void saveOriginalFile();
    void onSlotsEnumerated(int gen, const std::vector<fdo::Pkcs11Slot> &found,
                           const QString &error);
    void onSignFinished(int kind, bool ok, const QString &error,
                        const QByteArray &pdfOut);
    void issuePendingSlotQueries();

signals:
    void p11EnumerateRequested(const QString &libPath, int gen);
    void p11SignRequested(const Pkcs11Worker::SignParams &params);

private:
    // One pending slot-enumeration request (result applied to box/store).
    struct PendingSlots {
        int gen = 0;
        QString lib;
        QComboBox *box = nullptr;
        std::vector<fdo::Pkcs11Slot> *store = nullptr;
    };

    QWidget *buildPadesTab();
    QWidget *buildP7mTab();
    QWidget *buildVerifyTab();
    void detectSlots(QLineEdit *libEdit, QComboBox *slotBox,
                     std::vector<fdo::Pkcs11Slot> &store);
    void applySlotResults(QComboBox *box, std::vector<fdo::Pkcs11Slot> &store,
                          const std::vector<fdo::Pkcs11Slot> &found,
                          const std::string &err);
    fdo::Pkcs11Slot selectedSlot(QComboBox *box,
                                 const std::vector<fdo::Pkcs11Slot> &store) const;
    QString defaultP11Lib() const;
    void showProgress(const QString &text);
    void hideProgress();

    QTabWidget *m_tabs = nullptr;

    // PAdES tab
    QLineEdit *m_pdfInput = nullptr;
    QLineEdit *m_pdfOutput = nullptr;
    QLineEdit *m_p11Lib = nullptr;
    QComboBox *m_p11Slot = nullptr;
    QLineEdit *m_p11Pin = nullptr;
    QCheckBox *m_visible = nullptr;
    QLineEdit *m_visibleText = nullptr;
    QSpinBox *m_page = nullptr;
    QPushButton *m_signPdf = nullptr;
    QLabel *m_pdfStatus = nullptr;
    fdo::PdfPreview *m_preview = nullptr;
    QLabel *m_boxLabel = nullptr;

    // P7M tab
    QLineEdit *m_fileInput = nullptr;
    QLineEdit *m_fileOutput = nullptr;
    QLineEdit *m_p7mLib = nullptr;
    QComboBox *m_p7mSlot = nullptr;
    QLineEdit *m_p7mPin = nullptr;
    QPushButton *m_signFile = nullptr;
    QLabel *m_fileStatus = nullptr;

    // Verify tab
    QLineEdit *m_verifyP7m = nullptr;
    QLineEdit *m_verifyTsl = nullptr;
    QPushButton *m_verifyBtn = nullptr;
    QPushButton *m_saveOriginalBtn = nullptr;
    QPlainTextEdit *m_verifyReport = nullptr;
    QLabel *m_verifyStatus = nullptr;
    std::vector<unsigned char> m_verifyContent; // embedded content of last OK verify
    bool m_verifyContentReady = false;

    std::vector<fdo::Pkcs11Slot> m_p11Slots;
    std::vector<fdo::Pkcs11Slot> m_p7mSlots;

    // PKCS#11 runs on a worker thread so slow real-token calls never block
    // the UI; the modal progress dialog is shown while a sign is in flight.
    QThread *m_p11Thread = nullptr;
    Pkcs11Worker *m_p11Worker = nullptr;
    QTimer *m_slotDebounce = nullptr;
    QProgressDialog *m_progress = nullptr;
    int m_slotGen = 0;
    std::vector<PendingSlots> m_pendingSlots;
};
