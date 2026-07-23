#include <QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer>
#include <iostream>
#include <unistd.h>
#include "gui/MainWindow.h"

int main(int argc, char* argv[]) {
    if (geteuid() != 0) {
        std::cerr << "[!] WifiSec requires root privileges.\n"
                  << "    Run: sudo wifisec\n";
        return 1;
    }

    QApplication app(argc, argv);
    app.setApplicationName("WifiSec");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("WifiSec");

    // Splash screen
    QPixmap splash(400, 200);
    splash.fill(QColor(20, 20, 20));
    QSplashScreen splashScreen(splash);
    splashScreen.showMessage(
        "<span style='color:#00ff88; font-size:24px;'>"
        "<b>WifiSec v1.0</b></span><br>"
        "<span style='color:#aaaaaa;'>Industry Grade Wireless Security Tool</span><br><br>"
        "<span style='color:#ff4444;'>For authorized testing only</span>",
        Qt::AlignCenter);
    splashScreen.show();
    app.processEvents();

    MainWindow win;
    QTimer::singleShot(1500, [&](){
        splashScreen.finish(&win);
        win.show();
    });

    return app.exec();
}
