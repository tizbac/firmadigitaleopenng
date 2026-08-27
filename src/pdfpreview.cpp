#include "pdfpreview.h"

#include <QPainter>
#include <QMouseEvent>
#include <QScrollBar>

#include <poppler/qt6/poppler-qt6.h>

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

        // Permanent signature box (green).
        if (m_hasBox) {
            const QPointF tl = pdfToScreen(m_boxX1, m_boxY2); // left, top
            const QPointF br = pdfToScreen(m_boxX2, m_boxY1); // right, bottom
            QRectF r(qMin(tl.x(), br.x()), qMin(tl.y(), br.y()),
                     qAbs(br.x() - tl.x()), qAbs(br.y() - tl.y()));
            p.setPen(QPen(QColor(0, 160, 0), 2));
            p.setBrush(Qt::NoBrush);
            p.drawRect(r);
        }

        // In-progress drag rectangle (red).
        if (m_dragging) {
            QRectF r = QRectF(m_dragStart, m_dragCur).normalized();
            p.setPen(QPen(QColor(220, 0, 0), 2, Qt::DashLine));
            p.setBrush(QColor(220, 0, 0, 40));
            p.drawRect(r);
        }
    }
}

void PdfPreview::mousePressEvent(QMouseEvent *e)
{
    if (e->button() != Qt::LeftButton || m_image.isNull())
        return;
    m_dragging = true;
    m_dragStart = e->position();
    m_dragCur = m_dragStart;
    update();
}

void PdfPreview::mouseMoveEvent(QMouseEvent *e)
{
    if (!m_dragging)
        return;
    m_dragCur = e->position();
    update();
}

void PdfPreview::mouseReleaseEvent(QMouseEvent *e)
{
    if (e->button() != Qt::LeftButton || !m_dragging)
        return;
    m_dragging = false;
    m_dragCur = e->position();

    const QRectF screen = QRectF(m_dragStart, m_dragCur).normalized();
    // Ignore trivial clicks.
    if (screen.width() < 4 || screen.height() < 4) {
        update();
        return;
    }

    // Convert to PDF points (bottom-left origin).
    const QPointF tl = screenToPdf(screen.left(), screen.top());
    const QPointF br = screenToPdf(screen.right(), screen.bottom());
    m_boxX1 = tl.x();
    m_boxX2 = br.x();
    m_boxY2 = tl.y(); // top (larger PDF y)
    m_boxY1 = br.y(); // bottom (smaller PDF y)
    m_hasBox = true;
    update();
    emit boxChanged(true);
}

} // namespace fdo
