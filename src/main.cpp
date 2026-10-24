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

    // Command-line contract used by the Explorer integration:
    //   (no flag) file.pdf / file.p7m  -> verification tab (+ auto verify)
    //   --sign-pades <file.pdf>        -> PAdES tab, input preloaded
    //   --sign-p7m   <any file>        -> P7M tab, input preloaded
    //   --verify     <file>            -> verification tab
    enum class StartAction { Verify, SignPades, SignP7m };
    StartAction action = StartAction::Verify;
    QString path;

    const QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        const QString arg = args.at(i);
        if (arg == QLatin1String("--sign-pades")) {
            action = StartAction::SignPades;
        } else if (arg == QLatin1String("--sign-p7m")) {
            action = StartAction::SignP7m;
        } else if (arg == QLatin1String("--verify")) {
            action = StartAction::Verify;
        } else if (!arg.startsWith('-') && QFileInfo::exists(arg)) {
            path = arg;
            break;
        }
    }

    if (!path.isEmpty()) {
        switch (action) {
        case StartAction::SignPades:
            w.openFileForSignPades(path);
            break;
        case StartAction::SignP7m:
            w.openFileForSignP7m(path);
            break;
        case StartAction::Verify:
        default:
            w.openFileForVerify(path);
            break;
        }
    }
    return app.exec();
}
