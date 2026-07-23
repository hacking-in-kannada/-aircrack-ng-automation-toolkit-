#include "ScannerTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QGroupBox>
#include <algorithm>

ScannerTab::ScannerTab(QWidget* parent) : QWidget(parent) {
    setupUi();
}

void ScannerTab::setupUi() {
    auto* layout = new QVBoxLayout(this);

    // Controls
    auto* ctrlBox = new QGroupBox("Scan Control", this);
    auto* ctrlLayout = new QHBoxLayout(ctrlBox);
    m_startBtn = new QPushButton("Start Scan", this);
    m_startBtn->setStyleSheet(
        "QPushButton{background:#006600;color:white;padding:8px 20px;border-radius:4px;font-weight:bold;}"
        "QPushButton:hover{background:#008800;}");
    m_stopBtn = new QPushButton("Stop Scan", this);
    m_stopBtn->setStyleSheet(
        "QPushButton{background:#555;color:white;padding:8px 20px;border-radius:4px;}"
        "QPushButton:hover{background:#777;}");
    m_stopBtn->setEnabled(false);
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText("Filter by SSID or BSSID...");
    m_filterEdit->setStyleSheet("background:#2a2a2a;color:white;border:1px solid #555;padding:6px;border-radius:4px;");
    m_countLabel = new QLabel("Networks: 0", this);
    m_countLabel->setStyleSheet("color:#00ff88; font-weight:bold;");

    ctrlLayout->addWidget(m_startBtn);
    ctrlLayout->addWidget(m_stopBtn);
    ctrlLayout->addWidget(new QLabel("Filter:", this));
    ctrlLayout->addWidget(m_filterEdit);
    ctrlLayout->addStretch();
    ctrlLayout->addWidget(m_countLabel);

    // Table
    m_table = new QTableWidget(0, 8, this);
    m_table->setHorizontalHeaderLabels({"BSSID","SSID","Channel","Signal","Security","WPS","Clients","Last Seen"});
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setSortingEnabled(true);
    m_table->setStyleSheet(
        "QTableWidget{background:#1a1a1a;color:#ddd;gridline-color:#333;border:1px solid #444;}"
        "QTableWidget::item:selected{background:#00441a;color:white;}"
        "QHeaderView::section{background:#2d2d2d;color:#00ff88;padding:6px;border:1px solid #444;font-weight:bold;}");

    connect(m_startBtn,  &QPushButton::clicked, this, &ScannerTab::onStartScan);
    connect(m_stopBtn,   &QPushButton::clicked, this, &ScannerTab::onStopScan);
    connect(m_table,     &QTableWidget::itemSelectionChanged, this, &ScannerTab::onRowSelected);
    connect(m_filterEdit,&QLineEdit::textChanged, this, &ScannerTab::onFilter);

    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, &ScannerTab::refreshTable);

    layout->addWidget(ctrlBox);
    layout->addWidget(m_table);
}

void ScannerTab::setInterface(const std::string& iface) {
    m_iface = iface;
}

void ScannerTab::onStartScan() {
    if (m_iface.empty()) return;
    m_scanner = std::make_unique<Scanner>(m_iface);
    m_scanner->onNetworkFound([this](const NetworkInfo& net) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_networks.begin(), m_networks.end(),
            [&](const NetworkInfo& n){ return n.bssid == net.bssid; });
        if (it == m_networks.end()) m_networks.push_back(net);
        else *it = net;
    });
    m_scanner->start();
    m_startBtn->setEnabled(false);
    m_stopBtn->setEnabled(true);
    m_refreshTimer->start(2000);
}

void ScannerTab::onStopScan() {
    stopScan();
}

void ScannerTab::stopScan() {
    if (m_scanner) m_scanner->stop();
    m_refreshTimer->stop();
    m_startBtn->setEnabled(true);
    m_stopBtn->setEnabled(false);
}

void ScannerTab::refreshTable() {
    std::vector<NetworkInfo> nets;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        nets = m_networks;
    }
    QString filter = m_filterEdit->text().toLower();
    m_table->setSortingEnabled(false);
    for (const auto& net : nets) {
        QString ssid  = QString::fromStdString(net.ssid);
        QString bssid = QString::fromStdString(net.bssid);
        if (!filter.isEmpty() &&
            !ssid.toLower().contains(filter) &&
            !bssid.toLower().contains(filter)) continue;
        int row = findNetworkRow(net.bssid);
        if (row < 0) { m_table->insertRow(m_table->rowCount()); row = m_table->rowCount()-1; }
        updateNetworkRow(row, net);
    }
    m_table->setSortingEnabled(true);
    m_countLabel->setText(QString("Networks: %1").arg(nets.size()));
}

void ScannerTab::updateNetworkRow(int row, const NetworkInfo& net) {
    auto set = [&](int col, const QString& txt, const QColor& fg = Qt::white) {
        auto* item = new QTableWidgetItem(txt);
        item->setForeground(fg);
        m_table->setItem(row, col, item);
    };
    set(0, QString::fromStdString(net.bssid), QColor("#aaaaaa"));
    set(1, QString::fromStdString(net.ssid));
    set(2, QString::number(net.channel), QColor("#88ccff"));
    set(3, signalBar(net.signal_dbm),
        net.signal_dbm > -60 ? QColor("#00ff88") :
        net.signal_dbm > -75 ? QColor("#ffaa00") : QColor("#ff4444"));
    set(4, securityStr(net.security),
        net.security == Security::OPEN ? QColor("#ff4444") :
        net.security == Security::WPA3 ? QColor("#00ff88") : QColor("#ffaa00"));
    set(5, net.wps_enabled ? "YES" : "NO",
        net.wps_enabled ? QColor("#ff8800") : QColor("#555555"));
    set(6, QString::number(net.clients));
    set(7, QString::fromStdString(net.last_seen), QColor("#666666"));
    m_table->setRowHeight(row, 28);
}

int ScannerTab::findNetworkRow(const std::string& bssid) {
    for (int r = 0; r < m_table->rowCount(); r++) {
        auto* item = m_table->item(r, 0);
        if (item && item->text().toStdString() == bssid) return r;
    }
    return -1;
}

void ScannerTab::onRowSelected() {
    auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    int row = rows[0].row();
    auto* item = m_table->item(row, 0);
    if (!item) return;
    std::string bssid = item->text().toStdString();
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = std::find_if(m_networks.begin(), m_networks.end(),
        [&](const NetworkInfo& n){ return n.bssid == bssid; });
    if (it != m_networks.end()) emit networkSelected(*it);
}

void ScannerTab::onFilter(const QString&) { refreshTable(); }

QString ScannerTab::securityStr(Security s) {
    switch (s) {
        case Security::OPEN:      return "OPEN";
        case Security::WEP:       return "WEP";
        case Security::WPA:       return "WPA";
        case Security::WPA2:      return "WPA2";
        case Security::WPA3:      return "WPA3";
        case Security::WPA2_WPA3: return "WPA2/3";
        default:                   return "?";
    }
}

QString ScannerTab::signalBar(int dbm) {
    if (dbm >= -50) return QString("█████ %1 dBm").arg(dbm);
    if (dbm >= -60) return QString("████░ %1 dBm").arg(dbm);
    if (dbm >= -70) return QString("███░░ %1 dBm").arg(dbm);
    if (dbm >= -80) return QString("██░░░ %1 dBm").arg(dbm);
    return             QString("█░░░░ %1 dBm").arg(dbm);
}
