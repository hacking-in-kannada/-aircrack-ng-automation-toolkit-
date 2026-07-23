#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QGroupBox>
#include <QSpinBox>
#include "common/Types.h"
#include "core/Attacker.h"
#include <memory>

class AttackTab : public QWidget {
    Q_OBJECT
public:
    explicit AttackTab(QWidget* parent = nullptr);
    void setInterface(const std::string& iface);
    void stopAttack();

public slots:
    void setTarget(const NetworkInfo& net);

private slots:
    void onLaunchAttack();
    void onStopAttack();
    void onAttackResult(const AttackResult& result);

private:
    void setupUi();
    void updateTargetInfo();
    void log(const QString& msg, const QString& color = "#00ff88");

    QLabel*       m_targetLabel;
    QLabel*       m_secLabel;
    QLabel*       m_wpsLabel;
    QLabel*       m_channelLabel;
    QComboBox*    m_attackCombo;
    QPushButton*  m_launchBtn;
    QPushButton*  m_stopBtn;
    QProgressBar* m_progress;
    QTextEdit*    m_log;
    QSpinBox*     m_deauthCount;
    QSpinBox*     m_deauthDelay;

    NetworkInfo                  m_target;
    std::string                  m_iface;
    std::unique_ptr<Attacker>    m_attacker;
};
