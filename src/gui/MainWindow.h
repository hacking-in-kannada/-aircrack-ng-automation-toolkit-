#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QStatusBar>
#include <QTimer>
#include "ScannerTab.h"
#include "AttackTab.h"
#include "EvilTwinTab.h"
#include "CrackTab.h"
#include "StealthTab.h"
#include "utils/Logger.h"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void onIfaceChanged(int idx);
    void onStartMonitor();
    void onStopMonitor();
    void updateStatus();
    void onLogMessage(LogLevel level, const std::string& msg);

private:
    void setupUi();
    void setupMenu();
    void applyDarkTheme();
    void populateInterfaces();
    bool checkRoot();

    QTabWidget*   m_tabs;
    ScannerTab*   m_scannerTab;
    AttackTab*    m_attackTab;
    EvilTwinTab*  m_evilTwinTab;
    CrackTab*     m_crackTab;
    StealthTab*   m_stealthTab;
    QComboBox*    m_ifaceCombo;
    QPushButton*  m_monitorBtn;
    QPushButton*  m_stopBtn;
    QLabel*       m_statusLabel;
    QTimer*       m_statusTimer;
    std::string   m_currentIface;
};
