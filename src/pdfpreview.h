#pragma once

#include <QWidget>
#include <QImage>

#include <memory>

namespace Poppler {
class Document;
}

namespace fdo {

// Renders a single PDF page (via Poppler) and lets the user draw a rectangle
// with the mouse to place the visible PAdES stamp. The box is reported in PDF
// points with a bottom-left origin (boxX1/boxY1 = lower-left corner,
// boxX2/boxY2 = upper-right corner), matching fdo::PadesConfig.
class PdfPreview : public QWidget
{
    Q_OBJECT

public:
    explicit PdfPreview(QWidget *parent = nullptr);
    ~PdfPreview() override;

    // Load a document and render page `page` (0-based). Returns false with
    // *error set on failure.
    bool loadPdf(const QString &path, int page = 0, QString *error = nullptr);

    int pageCount() const;
    int page() const { return m_page; }

    bool hasBox() const { return m_hasBox; }
    // Box in PDF points, bottom-left origin.
    double boxX1() const { return m_boxX1; }
    double boxY1() const { return m_boxY1; }
    double boxX2() const { return m_boxX2; }
    double boxY2() const { return m_boxY2; }

    void clearBox();

    void setPage(int i);

signals:
    void boxChanged(bool hasBox);
    void pageChanged(int page);

protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void mouseReleaseEvent(QMouseEvent *) override;

private:
    void renderPage();
    QPointF pdfToScreen(double px, double py) const;
    QPointF screenToPdf(double sx, double sy) const;

    std::unique_ptr<Poppler::Document> m_doc;
    QImage m_image;
    int m_page = 0;
    double m_zoom = 1.5;   // rendered pixels per PDF point
    double m_pageW = 0;    // page size in PDF points
    double m_pageH = 0;

    bool m_hasBox = false;
    double m_boxX1 = 0, m_boxY1 = 0, m_boxX2 = 0, m_boxY2 = 0;

    bool m_dragging = false;
    QPointF m_dragStart;
    QPointF m_dragCur;
};

} // namespace fdo
