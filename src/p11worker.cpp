#include "p11worker.h"

#include <pades.h>
#include <p7m.h>
#include <x509util.h>

namespace {

std::vector<unsigned char> fromQByteArray(const QByteArray &b)
{
    return { b.constData(), b.constData() + b.size() };
}

QByteArray toQByteArray(const std::vector<unsigned char> &v)
{
    return { reinterpret_cast<const char *>(v.data()), static_cast<int>(v.size()) };
}

} // namespace

void Pkcs11Worker::enumerate(const QString &libPath, int gen)
{
    std::string err;
    const auto found = fdo::Pkcs11::enumerateSlots(libPath.toStdString(), &err);
    emit enumerated(gen, found, err.empty() ? QString() : QString::fromStdString(err));
}

void Pkcs11Worker::sign(const SignParams &params)
{
    const int kind = params.kind;
    std::string err;

    m_p11.close(); // drop any previous session before a new token operation
    if (!m_p11.loadLibrary(params.libPath.toStdString(), &err)) {
        emit signFinished(kind, false, QString::fromStdString(err), {});
        return;
    }
    if (!m_p11.login(params.slotIndex, params.pin.toStdString(), &err)) {
        emit signFinished(kind, false, QString::fromStdString(err), {});
        return;
    }
    if (!m_p11.findSigner(&err)) {
        emit signFinished(kind, false, QString::fromStdString(err), {});
        return;
    }
    const auto *signer = m_p11.signer();
    if (!signer || signer->certDer.empty()) {
        emit signFinished(kind, false, tr("Nessun certificato trovato."), {});
        return;
    }

    const fdo::SignFunction signFn = [this](const std::vector<unsigned char> &data,
                                            std::vector<unsigned char> &sig,
                                            std::string &e) {
        return m_p11.sign(data, sig, &e);
    };

    if (kind == SignParams::Pades) {
        auto cert = fdo::X509Cert::fromDer(signer->certDer);
        if (!cert) {
            emit signFinished(kind, false,
                              tr("Certificato non valido sul token."), {});
            return;
        }
        fdo::PadesConfig cfg;
        cfg.pdfBytes = fromQByteArray(params.pdfData);
        cfg.onPage = params.page;
        cfg.visible = params.visible;
        cfg.visibleText = params.visibleText;
        if (params.visible) {
            cfg.boxX1 = params.boxX1;
            cfg.boxY1 = params.boxY1;
            cfg.boxX2 = params.boxX2;
            cfg.boxY2 = params.boxY2;
        }
        cfg.signerCert = *cert;
        const fdo::PadesResult res = fdo::Pades::sign(cfg, signFn);
        if (!res.ok) {
            emit signFinished(kind, false, QString::fromStdString(res.error), {});
            return;
        }
        emit signFinished(kind, true, QString(), toQByteArray(res.pdfBytes));
    } else {
        const bool ok = fdo::P7M::signFile(params.p7mIn.toStdString(),
                                           params.p7mOut.toStdString(),
                                           signer->certDer, signFn, &err);
        emit signFinished(kind, ok, ok ? QString() : QString::fromStdString(err),
                          {});
    }
}
