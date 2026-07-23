#include "MainWindow.h"
#include "utils/NetUtils.h"
#include "utils/MacSpoofer.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextEdit>
#include <QDockWidget>
#include <QPalette>
#include <QFont>
#include <unistd.h>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("WifiSec — Industry Grade Wireless Security Tool");
    setMinimumSize(1200, 800);
    applyDarkTheme();
    setupUi();
    setupMenu();

    // Route logger to GUI
    Logger::instance().setCallback([this](LogLevel lvl, const std::string& msg) {
        QMetaObject::invokeMethod(this, [this, lvl, msg](){
            onLogMessage(lvl, msg);
        }, Qt::QueuedConnection);
    });

    m_statusTimer = new QTimer(this);
    connect(m_statusTimer, &QTimer::timeout, this, &MainWindow::updateStatus);
    m_statusTimer->start(2000);

    if (!checkRoot()) {
        QMessageBox::critical(this, "Root Required",
            "This tool requires root privileges.\nRun with: sudo wifisec");
    }
}

MainWindow::~MainWindow() {}

void MainWindow::setupUi() {
    auto* central = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(4, 4, 4, 4);
    mainLayout->setSpacing(4);

    // Top toolbar
    auto* toolbar = new QGroupBox(this);
    toolbar->setMaximumHeight(60);
    auto* tbLayout = new QHBoxLayout(toolbar);

    auto* ifaceLabel = new QLabel("Interface:", toolbar);
    ifaceLabel->setStyleSheet("font-weight:bold; color:#00ff88;");
    m_ifaceCombo = new QComboBox(toolbar);
    m_ifaceCombo->setMinimumWidth(140);
    m_ifaceCombo->setStyleSheet(
        "QComboBox { background:#2a2a2a; color:#ffffff; border:1px solid #555; padding:4px; }");
    populateInterfaces();

    m_monitorBtn = new QPushButton("Enable Monitor Mode", toolbar);
    m_monitorBtn->setStyleSheet(
        "QPushButton { background:#006600; color:white; padding:6px 14px; border-radius:4px; }"
        "QPushButton:hover { background:#008800; }");

    m_stopBtn = new QPushButton("Stop All", toolbar);
    m_stopBtn->setStyleSheet(
        "QPushButton { background:#880000; color:white; padding:6px 14px; border-radius:4px; }"
        "QPushButton:hover { background:#aa0000; }");

    m_statusLabel = new QLabel("Ready", toolbar);
    m_statusLabel->setStyleSheet("color:#aaaaaa; font-size:11px;");

    tbLayout->addWidget(ifaceLabel);
    tbLayout->addWidget(m_ifaceCombo);
    tbLayout->addWidget(m_monitorBtn);
    tbLayout->addWidget(m_stopBtn);
    tbLayout->addStretch();
    tbLayout->addWidget(m_statusLabel);

    connect(m_ifaceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onIfaceChanged);
    connect(m_monitorBtn, &QPushButton::clicked, this, &MainWindow::onStartMonitor);
    connect(m_stopBtn,    &QPushButton::clicked, this, &MainWindow::onStopMonitor);

    // Tabs
    m_tabs = new QTabWidget(this);
    m_tabs->setStyleSheet(
        "QTabWidget::pane { border:1px solid #333; }"
        "QTabBar::tab { background:#1e1e1e; color:#aaa; padding:8px 20px; }"
        "QTabBar::tab:selected { background:#2d2d2d; color:#00ff88; border-bottom:2px solid #00ff88; }");

    m_scannerTab  = new ScannerTab(this);
    m_attackTab   = new AttackTab(this);
    m_evilTwinTab = new EvilTwinTab(this);
    m_crackTab    = new CrackTab(this);
    m_stealthTab  = new StealthTab(this);

    m_tabs->addTab(m_scannerTab,  "  Scanner  ");
    m_tabs->addTab(m_attackTab,   "  Attack   ");
    m_tabs->addTab(m_evilTwinTab, " Evil Twin ");
    m_tabs->addTab(m_crackTab,    "  Cracker  ");
    m_tabs->addTab(m_stealthTab,  "  Stealth  ");

    // Log dock
    auto* logDock = new QDockWidget("Log", this);
    logDock->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetFloatable);
    auto* logWidget = new QTextEdit(logDock);
    logWidget->setObjectName("logWidget");
    logWidget->setReadOnly(true);
    logWidget->setMaximumHeight(150);
    logWidget->setStyleSheet("background:#0d0d0d; color:#00cc00; font-family:monospace; font-size:11px;");
    logDock->setWidget(logWidget);
    addDockWidget(Qt::BottomDockWidgetArea, logDock);

    mainLayout->addWidget(toolbar);
    mainLayout->addWidget(m_tabs);
    setCentralWidget(central);

    // Wire scanner to attack tab
    connect(m_scannerTab, &ScannerTab::networkSelected,
            m_attackTab,  &AttackTab::setTarget);
    connect(m_scannerTab, &ScannerTab::networkSelected,
            m_evilTwinTab, &EvilTwinTab::setTarget);

    // Wire iface changes to all tabs
    onIfaceChanged(0);
}

void MainWindow::setupMenu() {
    auto* fileMenu = menuBar()->addMenu("File");
    fileMenu->addAction("Load Capture...", [this](){
        QString f = QFileDialog::getOpenFileName(this, "Open Capture", "",
                    "Capture Files (*.cap *.pcap *.pcapng *.hash)");
        if (!f.isEmpty()) m_crackTab->loadCapture(f);
    });
    fileMenu->addAction("Export Report...", [](){});
    fileMenu->addSeparator();
    fileMenu->addAction("Quit", qApp, &QApplication::quit);

    auto* toolMenu = menuBar()->addMenu("Tools");
    toolMenu->addAction("Spoof MAC", [this](){
        MacSpoofer::spoof(m_currentIface);
    });
    toolMenu->addAction("Restore MAC", [this](){
        MacSpoofer::restore(m_currentIface);
    });

    auto* helpMenu = menuBar()->addMenu("Help");
    helpMenu->addAction("About", [this](){
        QMessageBox::about(this, "WifiSec",
            "<b>WifiSec v1.0</b><br>Industry-grade wireless security tool.<br>"
            "For authorized testing only.");
    });
}

void MainWindow::applyDarkTheme() {
    QPalette p;
    p.setColor(QPalette::Window,          QColor(30,  30,  30));
    p.setColor(QPalette::WindowText,      QColor(220, 220, 220));
    p.setColor(QPalette::Base,            QColor(18,  18,  18));
    p.setColor(QPalette::AlternateBase,   QColor(35,  35,  35));
    p.setColor(QPalette::Text,            QColor(220, 220, 220));
    p.setColor(QPalette::Button,          QColor(45,  45,  45));
    p.setColor(QPalette::ButtonText,      QColor(220, 220, 220));
    p.setColor(QPalette::Highlight,       QColor(0,   180, 100));
    p.setColor(QPalette::HighlightedText, Qt::black);
    p.setColor(QPalette::Link,            QColor(0,   200, 120));
    qApp->setPalette(p);
    qApp->setFont(QFont("Segoe UI", 10));
}

void MainWindow::populateInterfaces() {
    m_ifaceCombo->clear();
    auto ifaces = NetUtils::wirelessInterfaces();
    for (const auto& i : ifaces)
        m_ifaceCombo->addItem(QString::fromStdString(i));
    if (!ifaces.empty()) m_currentIface = ifaces[0];
}

void MainWindow::onIfaceChanged(int) {
    m_currentIface = m_ifaceCombo->currentText().toStdString();
    m_scannerTab->setInterface(m_currentIface);
    m_attackTab->setInterface(m_currentIface);
    m_evilTwinTab->setInterface(m_currentIface);
}

void MainWindow::onStartMonitor() {
    if (m_currentIface.empty()) return;
    NetUtils::setMonitorMode(m_currentIface);
    m_monitorBtn->setStyleSheet(
        "QPushButton { background:#004400; color:#00ff00; padding:6px 14px; border-radius:4px; }");
    m_monitorBtn->setText("Monitor Mode: ON");
    statusBar()->showMessage("Monitor mode enabled on " + QString::fromStdString(m_currentIface));
}

void MainWindow::onStopMonitor() {
    m_scannerTab->stopScan();
    m_attackTab->stopAttack();
    m_evilTwinTab->stopEvilTwin();
    NetUtils::setManagedMode(m_currentIface);
    m_monitorBtn->setText("Enable Monitor Mode");
    m_monitorBtn->setStyleSheet(
        "QPushButton { background:#006600; color:white; padding:6px 14px; border-radius:4px; }"
        "QPushButton:hover { background:#008800; }");
    statusBar()->showMessage("All attacks stopped. Interface restored.");
}

void MainWindow::updateStatus() {
    bool monMode = NetUtils::isMonitorMode(m_currentIface);
    m_statusLabel->setText(
        QString("Interface: %1 | Mode: %2 | Channel: %3")
        .arg(QString::fromStdString(m_currentIface))
        .arg(monMode ? "MONITOR" : "MANAGED")
        .arg(NetUtils::currentChannel(m_currentIface)));
}

void MainWindow::onLogMessage(LogLevel level, const std::string& msg) {
    auto* log = findChild<QTextEdit*>("logWidget");
    if (!log) return;
    QString color;
    switch (level) {
        case LogLevel::DEBUG:    color = "#555555"; break;
        case LogLevel::INFO:     color = "#00cc00"; break;
        case LogLevel::WARN:     color = "#ffaa00"; break;
        case LogLevel::ERROR_LVL:color = "#ff4444"; break;
        case LogLevel::CRITICAL: color = "#ff0000"; break;
    }
    log->append(QString("<span style='color:%1'>%2</span>")
                .arg(color).arg(QString::fromStdString(msg)));
}

bool MainWindow::checkRoot() {
    return geteuid() == 0;
}
