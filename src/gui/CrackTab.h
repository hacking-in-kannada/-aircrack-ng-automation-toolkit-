#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QCheckBox>
#include <QLineEdit>
#include "core/Cracker.h"
#include <memory>

class CrackTab : public QWidget {
    Q_OBJECT
public:
    explicit CrackTab(QWidget* parent = nullptr);
    void loadCapture(const QString& path);

private slots:
    void onBrowseCapture();
    void onBrowseWordlist();
    void onStartCrack();
    void onStopCrack();

private:
    void setupUi();
    void log(const QString& msg, const QString& color = "#00ff88");

    QLineEdit*    m_captureEdit;
    QLineEdit*    m_ssidEdit;
    QComboBox*    m_wordlistCombo;
    QCheckBox*    m_useRulesBox;
    QCheckBox*    m_useGpuBox;
    QPushButton*  m_startBtn;
    QPushButton*  m_stopBtn;
    QProgressBar* m_progress;
    QLabel*       m_passwordLabel;
    QTextEdit*    m_log;

    std::unique_ptr<Cracker> m_cracker;
};
