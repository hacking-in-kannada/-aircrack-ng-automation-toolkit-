#include "CrackTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QFileDialog>
#include <QPushButton>

CrackTab::CrackTab(QWidget* parent) : QWidget(parent) { setupUi(); }

void CrackTab::setupUi() {
    auto* layout = new QHBoxLayout(this);

    auto* left = new QWidget(this);
    left->setMaximumWidth(400);
    auto* leftLayout = new QVBoxLayout(left);

    auto* cfgBox = new QGroupBox("Crack Configuration", left);
    auto* cfgForm = new QFormLayout(cfgBox);

    auto* capRow = new QHBoxLayout();
    m_captureEdit = new QLineEdit(cfgBox);
    m_captureEdit->setPlaceholderText("Path to .cap / .hash / .pcapng");
    m_captureEdit->setStyleSheet("background:#2a2a2a;color:white;border:1px solid #555;padding:6px;border-radius:4px;");
    auto* browseCapBtn = new QPushButton("...", cfgBox);
    browseCapBtn->setMaximumWidth(32);
    capRow->addWidget(m_captureEdit);
    capRow->addWidget(browseCapBtn);

    m_ssidEdit = new QLineEdit(cfgBox);
    m_ssidEdit->setPlaceholderText("SSID (for aircrack-ng fallback)");
    m_ssidEdit->setStyleSheet("background:#2a2a2a;color:white;border:1px solid #555;padding:6px;border-radius:4px;");

    auto* wlRow = new QHBoxLayout();
    m_wordlistCombo = new QComboBox(cfgBox);
    m_wordlistCombo->setEditable(true);
    m_wordlistCombo->setStyleSheet(
        "QComboBox{background:#2a2a2a;color:white;border:1px solid #555;padding:6px;}"
        "QComboBox QAbstractItemView{background:#2a2a2a;color:white;}");
    for (const auto& wl : Cracker::defaultWordlists())
        m_wordlistCombo->addItem(QString::fromStdString(wl));
    auto* browseWlBtn = new QPushButton("...", cfgBox);
    browseWlBtn->setMaximumWidth(32);
    wlRow->addWidget(m_wordlistCombo, 1);
    wlRow->addWidget(browseWlBtn);

    m_useRulesBox = new QCheckBox("Apply hashcat rules (best64)", cfgBox);
    m_useGpuBox   = new QCheckBox("Use GPU (hashcat)", cfgBox);
    m_useGpuBox->setChecked(Cracker::hasGPU());

    cfgForm->addRow("Capture:", capRow);
    cfgForm->addRow("SSID:", m_ssidEdit);
    cfgForm->addRow("Wordlist:", wlRow);
    cfgForm->addRow("", m_useRulesBox);
    cfgForm->addRow("", m_useGpuBox);

    m_startBtn = new QPushButton("Start Cracking", left);
    m_startBtn->setStyleSheet(
        "QPushButton{background:#660000;color:white;padding:10px;border-radius:4px;font-weight:bold;font-size:13px;}"
        "QPushButton:hover{background:#880000;}");
    m_stopBtn = new QPushButton("Stop", left);
    m_stopBtn->setStyleSheet(
        "QPushButton{background:#555;color:white;padding:10px;border-radius:4px;}"
        "QPushButton:hover{background:#777;}");
    m_stopBtn->setEnabled(false);

    m_progress = new QProgressBar(left);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_progress->setStyleSheet(
        "QProgressBar{border:1px solid #555;border-radius:4px;background:#1a1a1a;}"
        "QProgressBar::chunk{background:#660000;}");

    m_passwordLabel = new QLabel("Password: -", left);
    m_passwordLabel->setStyleSheet("color:#ffff00; font-weight:bold; font-size:16px; padding:8px;"
                                   "background:#111; border:1px solid #555; border-radius:4px;");

    leftLayout->addWidget(cfgBox);
    leftLayout->addWidget(m_startBtn);
    leftLayout->addWidget(m_stopBtn);
    leftLayout->addWidget(m_progress);
    leftLayout->addWidget(m_passwordLabel);
    leftLayout->addStretch();

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    auto* logLabel = new QLabel("Cracker Output", right);
    logLabel->setStyleSheet("color:#ff4444; font-weight:bold;");
    m_log = new QTextEdit(right);
    m_log->setReadOnly(true);
    m_log->setStyleSheet(
        "background:#0d0d0d;color:#cc0000;font-family:monospace;font-size:11px;border:1px solid #333;");
    rightLayout->addWidget(logLabel);
    rightLayout->addWidget(m_log);

    layout->addWidget(left);
    layout->addWidget(right, 1);

    connect(browseCapBtn, &QPushButton::clicked, this, &CrackTab::onBrowseCapture);
    connect(browseWlBtn,  &QPushButton::clicked, this, &CrackTab::onBrowseWordlist);
    connect(m_startBtn,   &QPushButton::clicked, this, &CrackTab::onStartCrack);
    connect(m_stopBtn,    &QPushButton::clicked, this, &CrackTab::onStopCrack);
}

void CrackTab::loadCapture(const QString& path) {
    m_captureEdit->setText(path);
}

void CrackTab::onBrowseCapture() {
    QString f = QFileDialog::getOpenFileName(this, "Open Capture", "",
                "Capture Files (*.cap *.pcap *.pcapng *.hash *.hc22000)");
    if (!f.isEmpty()) m_captureEdit->setText(f);
}

void CrackTab::onBrowseWordlist() {
    QString f = QFileDialog::getOpenFileName(this, "Open Wordlist", "/usr/share/wordlists",
                "Text Files (*.txt);;All Files (*)");
    if (!f.isEmpty()) m_wordlistCombo->setCurrentText(f);
}

void CrackTab::onStartCrack() {
    QString cap = m_captureEdit->text().trimmed();
    QString wl  = m_wordlistCombo->currentText().trimmed();
    if (cap.isEmpty() || wl.isEmpty()) {
        log("Specify capture file and wordlist!", "#ff4444");
        return;
    }
    CrackJob job;
    job.handshake_file = cap.toStdString();
    job.ssid           = m_ssidEdit->text().toStdString();
    job.wordlist       = wl.toStdString();
    job.use_rules      = m_useRulesBox->isChecked();
    job.use_gpu        = m_useGpuBox->isChecked();

    m_cracker = std::make_unique<Cracker>();
    m_cracker->onProgress([this](int pct, const std::string& status){
        QMetaObject::invokeMethod(this, [this, pct, status]{
            m_progress->setValue(pct);
            log(QString::fromStdString(status), "#cc4400");
        }, Qt::QueuedConnection);
    });
    m_cracker->onFound([this](const std::string& pwd){
        QMetaObject::invokeMethod(this, [this, pwd]{
            m_passwordLabel->setText("PASSWORD: " + QString::fromStdString(pwd));
            m_passwordLabel->setStyleSheet(
                "color:#000; font-weight:bold; font-size:16px; padding:8px;"
                "background:#ffff00; border:1px solid #888; border-radius:4px;");
            log("PASSWORD FOUND: " + QString::fromStdString(pwd), "#ffff00");
            m_startBtn->setEnabled(true);
            m_stopBtn->setEnabled(false);
        }, Qt::QueuedConnection);
    });

    m_cracker->crack(job);
    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_progress->setValue(0);
    log("Cracking started...");
}

void CrackTab::onStopCrack() {
    if (m_cracker) m_cracker->stop();
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
    log("Cracking stopped.");
}

void CrackTab::log(const QString& msg, const QString& color) {
    m_log->append(QString("<span style='color:%1'>%2</span>").arg(color).arg(msg));
}
