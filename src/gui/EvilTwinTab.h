#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QTextEdit>
#include <QTableWidget>
#include "common/Types.h"
#include "core/EvilTwin.h"
#include <memory>

class EvilTwinTab : public QWidget {
    Q_OBJECT
public:
    explicit EvilTwinTab(QWidget* parent = nullptr);
    void setInterface(const std::string& iface);
    void stopEvilTwin();

public slots:
    void setTarget(const NetworkInfo& net);

private slots:
    void onStart();
    void onStop();
    void onCredCaptured(const QString& ip, const QString& pwd);

private:
    void setupUi();
    void log(const QString& msg, const QString& color = "#00ff88");

    QLabel*       m_targetLabel;
    QCheckBox*    m_captureCredsBox;
    QCheckBox*    m_dnsSpoofBox;
    QCheckBox*    m_deauthBox;
    QPushButton*  m_startBtn;
    QPushButton*  m_stopBtn;
    QTextEdit*    m_log;
    QTableWidget* m_credsTable;
    QLabel*       m_statusLabel;

    NetworkInfo                  m_target;
    std::string                  m_iface;
    std::unique_ptr<EvilTwin>    m_et;
};
