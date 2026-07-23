#include "AttackTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>

AttackTab::AttackTab(QWidget* parent) : QWidget(parent) {
    setupUi();
}

void AttackTab::setupUi() {
    auto* layout = new QHBoxLayout(this);

    // Left: Target info + attack options
    auto* leftPanel = new QWidget(this);
    leftPanel->setMaximumWidth(380);
    auto* leftLayout = new QVBoxLayout(leftPanel);

    // Target info
    auto* targetBox = new QGroupBox("Target", leftPanel);
    auto* targetForm = new QFormLayout(targetBox);
    targetForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    auto makeLabel = [](const QString& text) {
        auto* l = new QLabel(text);
        l->setStyleSheet("color:#00ff88; font-weight:bold; font-size:12px;");
        return l;
    };

    m_targetLabel  = makeLabel("None selected");
    m_secLabel     = makeLabel("-");
    m_wpsLabel     = makeLabel("-");
    m_channelLabel = makeLabel("-");

    targetForm->addRow("SSID:",     m_targetLabel);
    targetForm->addRow("Security:", m_secLabel);
    targetForm->addRow("WPS:",      m_wpsLabel);
    targetForm->addRow("Channel:",  m_channelLabel);

    // Attack selection
    auto* atkBox = new QGroupBox("Attack Configuration", leftPanel);
    auto* atkLayout = new QVBoxLayout(atkBox);

    m_attackCombo = new QComboBox(atkBox);
    m_attackCombo->addItem("Handshake Capture (WPA/WPA2)");
    m_attackCombo->addItem("PMKID Attack (clientless)");
    m_attackCombo->addItem("WPS Pixie-Dust Attack");
    m_attackCombo->addItem("WPS Brute Force");
    m_attackCombo->setStyleSheet(
        "QComboBox{background:#2a2a2a;color:white;border:1px solid #555;padding:6px;}"
        "QComboBox::drop-down{border:none;}"
        "QComboBox QAbstractItemView{background:#2a2a2a;color:white;}");

    auto* deauthBox = new QGroupBox("Deauth Settings", atkBox);
    auto* deauthForm = new QFormLayout(deauthBox);
    m_deauthCount = new QSpinBox(deauthBox);
    m_deauthCount->setRange(1, 100); m_deauthCount->setValue(5);
    m_deauthDelay = new QSpinBox(deauthBox);
    m_deauthDelay->setRange(50, 5000); m_deauthDelay->setValue(200);
    m_deauthDelay->setSuffix(" ms");
    deauthForm->addRow("Packets:", m_deauthCount);
    deauthForm->addRow("Delay:",   m_deauthDelay);

    m_launchBtn = new QPushButton("Launch Attack", atkBox);
    m_launchBtn->setStyleSheet(
        "QPushButton{background:#880000;color:white;padding:10px;border-radius:4px;font-weight:bold;font-size:13px;}"
        "QPushButton:hover{background:#aa0000;}"
        "QPushButton:disabled{background:#444;}");
    m_stopBtn = new QPushButton("Stop", atkBox);
    m_stopBtn->setStyleSheet(
        "QPushButton{background:#555;color:white;padding:10px;border-radius:4px;}"
        "QPushButton:hover{background:#777;}");
    m_stopBtn->setEnabled(false);

    m_progress = new QProgressBar(atkBox);
    m_progress->setRange(0, 0);  // indeterminate
    m_progress->setVisible(false);
    m_progress->setStyleSheet(
        "QProgressBar{border:1px solid #555;border-radius:4px;background:#1a1a1a;height:16px;}"
        "QProgressBar::chunk{background:#00880044;}");

    atkLayout->addWidget(m_attackCombo);
    atkLayout->addWidget(deauthBox);
    atkLayout->addWidget(m_launchBtn);
    atkLayout->addWidget(m_stopBtn);
    atkLayout->addWidget(m_progress);

    leftLayout->addWidget(targetBox);
    leftLayout->addWidget(atkBox);
    leftLayout->addStretch();

    // Right: Log output
    auto* rightPanel = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(rightPanel);
    auto* logLabel = new QLabel("Attack Log", rightPanel);
    logLabel->setStyleSheet("color:#00ff88; font-weight:bold;");
    m_log = new QTextEdit(rightPanel);
    m_log->setReadOnly(true);
    m_log->setStyleSheet(
        "background:#0d0d0d; color:#00cc00; font-family:monospace; font-size:11px; border:1px solid #333;");
    rightLayout->addWidget(logLabel);
    rightLayout->addWidget(m_log);

    layout->addWidget(leftPanel);
    layout->addWidget(rightPanel, 1);

    connect(m_launchBtn, &QPushButton::clicked, this, &AttackTab::onLaunchAttack);
    connect(m_stopBtn,   &QPushButton::clicked, this, &AttackTab::onStopAttack);
}

void AttackTab::setInterface(const std::string& iface) { m_iface = iface; }

void AttackTab::setTarget(const NetworkInfo& net) {
    m_target = net;
    m_targetLabel->setText(QString::fromStdString(net.ssid) + " [" +
                           QString::fromStdString(net.bssid) + "]");
    const char* secNames[] = {"OPEN","WEP","WPA","WPA2","WPA3","WPA2/3"};
    m_secLabel->setText(secNames[(int)net.security]);
    m_wpsLabel->setText(net.wps_enabled ? "Enabled" : "Disabled");
    m_channelLabel->setText(QString::number(net.channel));
    log("Target set: " + QString::fromStdString(net.ssid));
}

void AttackTab::onLaunchAttack() {
    if (m_target.bssid.empty()) {
        log("No target selected!", "#ff4444");
        return;
    }
    m_attacker = std::make_unique<Attacker>(m_iface);
    m_attacker->setResultCallback([this](const AttackResult& r){
        QMetaObject::invokeMethod(this, [this, r]{ onAttackResult(r); }, Qt::QueuedConnection);
    });

    StealthConfig stealth;
    stealth.rate_limit_deauth = true;
    stealth.deauth_delay_ms   = m_deauthDelay->value();

    int idx = m_attackCombo->currentIndex();
    if      (idx == 0) { m_attacker->attackHandshake(m_target, stealth); log("Handshake capture started..."); }
    else if (idx == 1) { m_attacker->attackPMKID(m_target);              log("PMKID attack started..."); }
    else if (idx == 2) { m_attacker->attackWPS(m_target);                log("WPS Pixie-Dust started..."); }
    else if (idx == 3) { m_attacker->attackWPS(m_target);                log("WPS Brute Force started..."); }

    m_launchBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_progress->setVisible(true);
}

void AttackTab::onStopAttack() { stopAttack(); }

void AttackTab::stopAttack() {
    if (m_attacker) m_attacker->stopAttack();
    m_launchBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    m_progress->setVisible(false);
    log("Attack stopped.");
}

void AttackTab::onAttackResult(const AttackResult& r) {
    m_progress->setVisible(false);
    m_launchBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);

    if (r.status == AttackStatus::SUCCESS) {
        log("SUCCESS: " + QString::fromStdString(r.message), "#00ff88");
        if (!r.handshake_file.empty())
            log("Capture: " + QString::fromStdString(r.handshake_file), "#88ccff");
        if (!r.password.empty())
            log("PASSWORD: " + QString::fromStdString(r.password), "#ffff00");
    } else {
        log("FAILED: " + QString::fromStdString(r.message), "#ff4444");
    }
}

void AttackTab::log(const QString& msg, const QString& color) {
    m_log->append(QString("<span style='color:%1'>%2</span>").arg(color).arg(msg));
}
