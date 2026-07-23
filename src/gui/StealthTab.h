#pragma once
#include <QWidget>
#include <QCheckBox>
#include <QSpinBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include "common/Types.h"

class StealthTab : public QWidget {
    Q_OBJECT
public:
    explicit StealthTab(QWidget* parent = nullptr);
    StealthConfig config() const;

private slots:
    void onSpoofMac();
    void onRestoreMac();
    void onKillProcesses();

private:
    void setupUi();
    void log(const QString& msg, const QString& color = "#00ff88");

    QCheckBox*   m_spoofMacBox;
    QCheckBox*   m_rateLimitBox;
    QCheckBox*   m_randomBox;
    QCheckBox*   m_channelHopBox;
    QSpinBox*    m_deauthDelaySpin;
    QPushButton* m_spoofBtn;
    QPushButton* m_restoreBtn;
    QPushButton* m_killBtn;
    QTextEdit*   m_log;
    QLabel*      m_macLabel;
};
