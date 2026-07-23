#include "EvilTwinTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QDateTime>

EvilTwinTab::EvilTwinTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void EvilTwinTab::setupUi() {
    auto* layout = new QHBoxLayout(this);

    // Left panel
    auto* left = new QWidget(this);
    left->setMaximumWidth(360);
    auto* leftLayout = new QVBoxLayout(left);

    auto* targetBox = new QGroupBox("Target", left);
    auto* tf = new QFormLayout(targetBox);
    m_targetLabel = new QLabel("None selected", targetBox);
    m_targetLabel->setStyleSheet("color:#00ff88; font-weight:bold;");
    tf->addRow("Target:", m_targetLabel);

    auto* cfgBox = new QGroupBox("Configuration", left);
    auto* cfgLayout = new QVBoxLayout(cfgBox);
    m_captureCredsBox = new QCheckBox("Capture credentials via captive portal", cfgBox);
    m_captureCredsBox->setChecked(true);
    m_dnsSpoofBox = new QCheckBox("DNS spoofing (redirect all domains)", cfgBox);
    m_dnsSpoofBox->setChecked(true);
    m_deauthBox = new QCheckBox("Continuous deauth on real AP", cfgBox);
    m_deauthBox->setChecked(true);
    cfgLayout->addWidget(m_captureCredsBox);
    cfgLayout->addWidget(m_dnsSpoofBox);
    cfgLayout->addWidget(m_deauthBox);

    m_startBtn = new QPushButton("Start Evil Twin", left);
    m_startBtn->setStyleSheet(
        "QPushButton{background:#662200;color:white;padding:10px;border-radius:4px;font-weight:bold;font-size:13px;}"
        "QPushButton:hover{background:#883300;}");
    m_stopBtn = new QPushButton("Stop", left);
    m_stopBtn->setStyleSheet(
        "QPushButton{background:#555;color:white;padding:10px;border-radius:4px;}"
        "QPushButton:hover{background:#777;}");
    m_stopBtn->setEnabled(false);

    m_statusLabel = new QLabel("Status: Idle", left);
    m_statusLabel->setStyleSheet("color:#aaaaaa;");

    leftLayout->addWidget(targetBox);
    leftLayout->addWidget(cfgBox);
    leftLayout->addWidget(m_startBtn);
    leftLayout->addWidget(m_stopBtn);
    leftLayout->addWidget(m_statusLabel);
    leftLayout->addStretch();

    // Right panel
    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);

    auto* credsBox = new QGroupBox("Captured Credentials", right);
    auto* credsLayout = new QVBoxLayout(credsBox);
    m_credsTable = new QTableWidget(0, 3, credsBox);
    m_credsTable->setHorizontalHeaderLabels({"Time", "Client IP", "Password"});
    m_credsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_credsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_credsTable->setStyleSheet(
        "QTableWidget{background:#1a1a1a;color:#ddd;gridline-color:#333;}"
        "QTableWidget::item:selected{background:#663300;}"
        "QHeaderView::section{background:#2d2d2d;color:#ff8800;padding:6px;font-weight:bold;}");
    credsLayout->addWidget(m_credsTable);

    m_log = new QTextEdit(right);
    m_log->setReadOnly(true);
    m_log->setMaximumHeight(200);
    m_log->setStyleSheet(
        "background:#0d0d0d;color:#cc6600;font-family:monospace;font-size:11px;border:1px solid #333;");

    rightLayout->addWidget(credsBox, 1);
    rightLayout->addWidget(m_log);

    layout->addWidget(left);
    layout->addWidget(right, 1);

    connect(m_startBtn, &QPushButton::clicked, this, &EvilTwinTab::onStart);
    connect(m_stopBtn,  &QPushButton::clicked, this, &EvilTwinTab::onStop);
}

void EvilTwinTab::setInterface(const std::string& iface) { m_iface = iface; }

void EvilTwinTab::setTarget(const NetworkInfo& net) {
    m_target = net;
    m_targetLabel->setText(QString::fromStdString(net.ssid) + " [" +
                           QString::fromStdString(net.bssid) + "]");
}

void EvilTwinTab::onStart() {
    if (m_target.bssid.empty()) { log("No target selected!", "#ff4444"); return; }
    EvilTwinConfig cfg;
    cfg.target_ssid   = m_target.ssid;
    cfg.target_bssid  = m_target.bssid;
    cfg.channel       = m_target.channel;
    cfg.interface     = m_iface;
    cfg.capture_creds = m_captureCredsBox->isChecked();
    cfg.dns_spoof     = m_dnsSpoofBox->isChecked();

    m_et = std::make_unique<EvilTwin>();
    m_et->onLog([this](const std::string& msg){
        QMetaObject::invokeMethod(this, [this, msg]{ log(QString::fromStdString(msg)); },
                                  Qt::QueuedConnection);
    });
    m_et->onCred([this](const std::string& user, const std::string& pass){
        QMetaObject::invokeMethod(this, [this, user, pass]{
            onCredCaptured(QString::fromStdString(user), QString::fromStdString(pass));
        }, Qt::QueuedConnection);
    });

    m_et->start(cfg);
    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_statusLabel->setText("Status: RUNNING");
    m_statusLabel->setStyleSheet("color:#ff4444; font-weight:bold;");
    log("Evil Twin started for " + QString::fromStdString(m_target.ssid));
}

void EvilTwinTab::onStop() { stopEvilTwin(); }

void EvilTwinTab::stopEvilTwin() {
    if (m_et) m_et->stop();
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    m_statusLabel->setText("Status: Stopped");
    m_statusLabel->setStyleSheet("color:#aaaaaa;");
    log("Evil Twin stopped.");
}

void EvilTwinTab::onCredCaptured(const QString& ip, const QString& pwd) {
    int row = m_credsTable->rowCount();
    m_credsTable->insertRow(row);
    auto now = QDateTime::currentDateTime().toString("hh:mm:ss");
    m_credsTable->setItem(row, 0, new QTableWidgetItem(now));
    m_credsTable->setItem(row, 1, new QTableWidgetItem(ip));
    auto* pwdItem = new QTableWidgetItem(pwd);
    pwdItem->setForeground(QColor("#ffff00"));
    m_credsTable->setItem(row, 2, pwdItem);
    log("CREDENTIAL: " + ip + " -> " + pwd, "#ffff00");
}

void EvilTwinTab::log(const QString& msg, const QString& color) {
    m_log->append(QString("<span style='color:%1'>%2</span>").arg(color).arg(msg));
}
