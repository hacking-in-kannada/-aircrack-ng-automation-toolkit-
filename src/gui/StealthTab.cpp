#include "StealthTab.h"
#include "utils/MacSpoofer.h"
#include "utils/NetUtils.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>

StealthTab::StealthTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void StealthTab::setupUi() {
    auto* layout = new QHBoxLayout(this);

    auto* left = new QWidget(this);
    left->setMaximumWidth(400);
    auto* leftLayout = new QVBoxLayout(left);

    auto* macBox = new QGroupBox("MAC Address", left);
    auto* macLayout = new QVBoxLayout(macBox);
    m_macLabel = new QLabel("Current MAC: detecting...", macBox);
    m_macLabel->setStyleSheet("color:#88ccff; font-family:monospace;");
    m_spoofBtn = new QPushButton("Randomize MAC", macBox);
    m_spoofBtn->setStyleSheet(
        "QPushButton{background:#004466;color:white;padding:8px;border-radius:4px;}"
        "QPushButton:hover{background:#006688;}");
    m_restoreBtn = new QPushButton("Restore Original MAC", macBox);
    m_restoreBtn->setStyleSheet(
        "QPushButton{background:#444;color:white;padding:8px;border-radius:4px;}"
        "QPushButton:hover{background:#666;}");
    macLayout->addWidget(m_macLabel);
    macLayout->addWidget(m_spoofBtn);
    macLayout->addWidget(m_restoreBtn);

    auto* stealthBox = new QGroupBox("Evasion Settings", left);
    auto* sf = new QFormLayout(stealthBox);
    m_rateLimitBox  = new QCheckBox("Rate-limit deauth packets", stealthBox);
    m_rateLimitBox->setChecked(true);
    m_randomBox     = new QCheckBox("Random deauth intervals", stealthBox);
    m_randomBox->setChecked(true);
    m_channelHopBox = new QCheckBox("Channel hopping during scan", stealthBox);
    m_channelHopBox->setChecked(true);
    m_deauthDelaySpin = new QSpinBox(stealthBox);
    m_deauthDelaySpin->setRange(50, 10000);
    m_deauthDelaySpin->setValue(300);
    m_deauthDelaySpin->setSuffix(" ms");
    sf->addRow("", m_rateLimitBox);
    sf->addRow("", m_randomBox);
    sf->addRow("", m_channelHopBox);
    sf->addRow("Deauth delay:", m_deauthDelaySpin);

    m_killBtn = new QPushButton("Kill Interfering Processes", left);
    m_killBtn->setStyleSheet(
        "QPushButton{background:#444;color:white;padding:8px;border-radius:4px;}"
        "QPushButton:hover{background:#666;}");
    m_killBtn->setToolTip("Kills NetworkManager, wpa_supplicant etc. that may block monitor mode");

    leftLayout->addWidget(macBox);
    leftLayout->addWidget(stealthBox);
    leftLayout->addWidget(m_killBtn);
    leftLayout->addStretch();

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    auto* logLabel = new QLabel("Stealth Log", right);
    logLabel->setStyleSheet("color:#88ccff; font-weight:bold;");
    m_log = new QTextEdit(right);
    m_log->setReadOnly(true);
    m_log->setStyleSheet(
        "background:#0d0d0d;color:#0088cc;font-family:monospace;font-size:11px;border:1px solid #333;");
    rightLayout->addWidget(logLabel);
    rightLayout->addWidget(m_log);

    layout->addWidget(left);
    layout->addWidget(right, 1);

    connect(m_spoofBtn,   &QPushButton::clicked, this, &StealthTab::onSpoofMac);
    connect(m_restoreBtn, &QPushButton::clicked, this, &StealthTab::onRestoreMac);
    connect(m_killBtn,    &QPushButton::clicked, this, &StealthTab::onKillProcesses);
}

StealthConfig StealthTab::config() const {
    StealthConfig c;
    c.spoof_mac          = m_spoofBtn->isChecked();
    c.rate_limit_deauth  = m_rateLimitBox->isChecked();
    c.deauth_delay_ms    = m_deauthDelaySpin->value();
    c.random_intervals   = m_randomBox->isChecked();
    c.hop_channels       = m_channelHopBox->isChecked();
    return c;
}

void StealthTab::onSpoofMac() {
    auto ifaces = NetUtils::wirelessInterfaces();
    if (ifaces.empty()) { log("No wireless interface found!", "#ff4444"); return; }
    MacSpoofer::spoof(ifaces[0]);
    std::string newMac = MacSpoofer::current(ifaces[0]);
    m_macLabel->setText("Current MAC: " + QString::fromStdString(newMac));
    log("MAC spoofed: " + QString::fromStdString(newMac));
}

void StealthTab::onRestoreMac() {
    auto ifaces = NetUtils::wirelessInterfaces();
    if (ifaces.empty()) return;
    MacSpoofer::restore(ifaces[0]);
    std::string mac = MacSpoofer::current(ifaces[0]);
    m_macLabel->setText("Current MAC: " + QString::fromStdString(mac));
    log("MAC restored: " + QString::fromStdString(mac), "#aaaaaa");
}

void StealthTab::onKillProcesses() {
    std::system("airmon-ng check kill 2>/dev/null");
    log("Killed: NetworkManager, wpa_supplicant, dhclient");
}

void StealthTab::log(const QString& msg, const QString& color) {
    m_log->append(QString("<span style='color:%1'>%2</span>").arg(color).arg(msg));
}
