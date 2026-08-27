#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>

#include <string>
#include <vector>

#include "pkcs11.h"

// Runs the slow PKCS#11 operations (slot enumeration, token login, hardware
// signing) on a dedicated QThread. Real tokens (Bit4id) take seconds per C_*
// call - PIN entry on the token display, USB round trips - and must never
// block the GUI thread. Move this object to a worker thread and invoke the
// slots through queued connections; results come back via signals.
class Pkcs11Worker : public QObject
{
    Q_OBJECT

public:
    struct SignParams {
        enum Kind { Pades, P7M } kind = Pades;
        QString libPath;
        unsigned long slotIndex = 0;
        QString pin;
        // PAdES
        QByteArray pdfData;
        int page = 0;
        bool visible = false;
        std::string visibleText;
        double boxX1 = 0, boxY1 = 0, boxX2 = 0, boxY2 = 0;
        // P7M
        QString p7mIn;
        QString p7mOut;
    };

    explicit Pkcs11Worker(QObject *parent = nullptr) : QObject(parent) {}

public slots:
    void enumerate(const QString &libPath, int gen);
    void sign(const SignParams &params);

signals:
    void enumerated(int gen, const std::vector<fdo::Pkcs11Slot> &found,
                    const QString &error);
    void signFinished(int kind, bool ok, const QString &error,
                      const QByteArray &pdfOut);

private:
    fdo::Pkcs11 m_p11; // created and used only on the worker thread
};

Q_DECLARE_METATYPE(fdo::Pkcs11Slot)
Q_DECLARE_METATYPE(std::vector<fdo::Pkcs11Slot>)
Q_DECLARE_METATYPE(Pkcs11Worker::SignParams)
