#include <QApplication>
#include <QFileInfo>
#include <QStringList>

#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("FirmaDigitaleOpen");
    app.setOrganizationName("FirmaDigitaleOpen");
    app.setApplicationDisplayName("FirmaDigitaleOpen");
    MainWindow w;
    w.show();

    // A file passed on the command line (e.g. from the .pdf/.p7m file
    // association) is opened in the verification tab and verified immediately.
    const QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        const QString path = args.at(i);
        if (path.startsWith('-'))
            continue;
        if (QFileInfo::exists(path)) {
            w.openFileForVerify(path);
            break;
        }
    }
    return app.exec();
}
