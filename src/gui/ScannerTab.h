#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QLineEdit>
#include "common/Types.h"
#include "core/Scanner.h"
#include <memory>

class ScannerTab : public QWidget {
    Q_OBJECT
public:
    explicit ScannerTab(QWidget* parent = nullptr);
    void setInterface(const std::string& iface);
    void stopScan();

signals:
    void networkSelected(const NetworkInfo& net);

private slots:
    void onStartScan();
    void onStopScan();
    void onRowSelected();
    void refreshTable();
    void onFilter(const QString& text);

private:
    void setupUi();
    void addNetworkRow(const NetworkInfo& net);
    void updateNetworkRow(int row, const NetworkInfo& net);
    int  findNetworkRow(const std::string& bssid);
    QString securityStr(Security s);
    QString signalBar(int dbm);

    QTableWidget*              m_table;
    QPushButton*               m_startBtn;
    QPushButton*               m_stopBtn;
    QLabel*                    m_countLabel;
    QLineEdit*                 m_filterEdit;
    QTimer*                    m_refreshTimer;
    std::unique_ptr<Scanner>   m_scanner;
    std::string                m_iface;
    std::vector<NetworkInfo>   m_networks;
    std::mutex                 m_mutex;
};
