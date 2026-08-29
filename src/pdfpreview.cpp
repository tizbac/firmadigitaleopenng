#include "pdfpreview.h"

#include <QPainter>
#include <QMouseEvent>
#include <QScrollBar>

#include <algorithm>
#include <ctime>

#include <poppler/qt6/poppler-qt6.h>

#include "pades.h"

namespace fdo {

PdfPreview::PdfPreview(QWidget *parent)
    : QWidget(parent)
{
    setMinimumSize(200, 200);
    setCursor(Qt::CrossCursor);
}

// Defined here (not inline) so the unique_ptr<Poppler::Document> is destroyed
// where the complete type is visible.
PdfPreview::~PdfPreview() = default;

int PdfPreview::pageCount() const
{
    return m_doc ? m_doc->numPages() : 0;
}

QSizeF PdfPreview::pageSize() const
{
    return QSizeF(m_pageW, m_pageH);
}

bool PdfPreview::loadPdf(const QString &path, int page, QString *error)
{
    m_doc = Poppler::Document::load(path);
    if (!m_doc || m_doc->numPages() == 0) {
        m_doc.reset();
        if (error)
            *error = tr("Impossibile aprire il PDF: %1").arg(path);
        return false;
    }
    const int n = m_doc->numPages();
    m_page = qBound(0, page, n - 1);
    renderPage();
    return true;
}

void PdfPreview::setPage(int i)
{
    if (!m_doc || m_doc->numPages() == 0)
        return;
    m_page = qBound(0, i, m_doc->numPages() - 1);
    clearBox();
    renderPage();
    emit pageChanged(m_page);
}

void PdfPreview::setStampInfo(const QString &visibleText, const QString &signerName)
{
    m_stampText = visibleText;
    m_stampName = signerName;
    update();
}

void PdfPreview::clearBox()
{
    m_hasBox = false;
    m_boxX1 = m_boxY1 = m_boxX2 = m_boxY2 = 0;
    update();
    emit boxChanged(false);
}

void PdfPreview::renderPage()
{
    if (!m_doc)
        return;
    auto page = m_doc->page(m_page);
    if (!page)
        return;

    const QSizeF sz = page->pageSizeF();
    m_pageW = sz.width();
    m_pageH = sz.height();

    // Fit the page to a width that fits the preview pane (the pane is capped
    // at ~700 px); taller pages scroll vertically. This keeps the main window
    // from growing when a PDF is loaded.
    constexpr double kMaxWidth = 660.0;
    double zoom = kMaxWidth / (m_pageW > 0 ? m_pageW : 1.0);
    m_zoom = qBound(0.6, zoom, 2.5);

    m_image = page->renderToImage(72.0 * m_zoom, 72.0 * m_zoom);
    setFixedSize(m_image.size());
    update();
}

QPointF PdfPreview::pdfToScreen(double px, double py) const
{
    return QPointF(px * m_zoom, (m_pageH - py) * m_zoom);
}

QPointF PdfPreview::screenToPdf(double sx, double sy) const
{
    return QPointF(sx / m_zoom, m_pageH - sy / m_zoom);
}

void PdfPreview::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), QColor(120, 120, 120));

    if (m_image.isNull()) {
        p.setPen(Qt::white);
        p.drawText(rect(), Qt::AlignCenter,
                   tr("Carica un PDF per tracciare il riquadro della firma"));
        return;
    }

    {
        p.drawImage(0, 0, m_image);

        // Signature stamp preview: what Pades::sign will render.
        if (m_hasBox) {
            const QPointF tl = pdfToScreen(m_boxX1, m_boxY2); // left, top
            const QPointF br = pdfToScreen(m_boxX2, m_boxY1); // right, bottom
            QRectF r(qMin(tl.x(), br.x()), qMin(tl.y(), br.y()),
                     qAbs(br.x() - tl.x()), qAbs(br.y() - tl.y()));

            const std::string name = m_stampName.toStdString();
            const std::string line1 =
                m_stampText.toStdString() + " : " + name;
            const std::string line2 =
                "Time: " + stampTimeString(std::time(nullptr));
            const StampLayout sl =
                stampLayout(line1, line2, m_boxX2 - m_boxX1, m_boxY2 - m_boxY1,
                            m_maxFont);

            p.setPen(QPen(QColor(0, 160, 0), 2));
            p.fillRect(r, QColor(255, 255, 255, 230));
            p.drawRect(r);

            QFont font;
            font.setFamily(QStringLiteral("Helvetica"));
            font.setPixelSize(qMax(4, qRound(sl.fs * m_zoom)));
            p.setFont(font);
            p.setPen(QColor(20, 20, 20));

            // drawText uses the top-left of the text; emulate the baseline.
            const double ascent = 0.75 * sl.fs * m_zoom;
            const QPointF b1 =
                pdfToScreen(m_boxX1 + sl.left, m_boxY1 + sl.y1);
            const QPointF b2 =
                pdfToScreen(m_boxX1 + sl.left, m_boxY1 + sl.y2);
            p.drawText(QPointF(b1.x(), b1.y() - ascent),
                       QString::fromStdString(line1));
            p.drawText(QPointF(b2.x(), b2.y() - ascent),
                       QString::fromStdString(line2));
        }
    }
}

void PdfPreview::mousePressEvent(QMouseEvent *e)
{
    if (e->button() != Qt::LeftButton || m_image.isNull())
        return;
    placeStampAt(screenToPdf(e->position().x(), e->position().y()));
}

void PdfPreview::placeStampAt(const QPointF &pdfPos)
{
    const std::string name = m_stampName.toStdString();
    const std::string line1 = m_stampText.toStdString() + " : " + name;
    const std::string line2 = "Time: " + stampTimeString(std::time(nullptr));
    const StampBox fit = stampFitBox(line1, line2, m_maxFont);

    double w = fit.w;
    double h = fit.h;
    if (m_pageW > 24)
        w = std::min(w, m_pageW - 24.0);
    if (m_pageH > 24)
        h = std::min(h, m_pageH - 24.0);

    double x1 = pdfPos.x() - w / 2.0;
    double y1 = pdfPos.y() - h / 2.0;
    x1 = std::max(0.0, std::min(x1, m_pageW - w));
    y1 = std::max(0.0, std::min(y1, m_pageH - h));

    m_boxX1 = x1;
    m_boxY1 = y1;
    m_boxX2 = x1 + w;
    m_boxY2 = y1 + h;
    m_hasBox = true;
    update();
    emit boxChanged(true);
}

} // namespace fdo
