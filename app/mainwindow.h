#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableView>
#include <QTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QTabWidget>
#include <QSplitter>
#include <QDockWidget>
#include <memory>
#include "pipe_sniffer_integrated.h"
#include "packetmodel.h"
#include "packetdata.h"
#include "mvp_interfaces.h"
#include "eventbus.h"
#include "packet_repository.h"
#include "filter_delegate.h"

class MainWindow : public QMainWindow, public IPacketSnifferView {
    Q_OBJECT
    
public:
    explicit MainWindow(
        std::shared_ptr<EventBus> eventBus,
        std::shared_ptr<IPacketRepository> repository,
        QWidget *parent = nullptr);
    ~MainWindow();
    
    // IPacketSnifferView interface implementation
    void displayPackets(const std::vector<PacketDataPtr>& packets) override;
    void displayPacketDetails(const PacketDataPtr& packet) override;
    void setDeviceList(const std::vector<std::string>& devices) override;
    void updateStatistics(int totalPackets, int displayedPackets, uint64_t totalBytes) override;
    void setCaptureState(bool capturing) override;
    void showMessage(const std::string& message) override;
    void showError(const std::string& error) override;
    
    // UI Slots
    void onStartCaptureClicked();
    void onStopCaptureClicked();
    void onClearPacketsClicked();
    void onDeviceChangedUI(int index);
    void onFilterChangedUI(const QString& text);
    void onPacketSelectedUI(const QModelIndex& index);
    void onPacketDoubleClicked(const QModelIndex& index); // New slot for double click
    void onExportCSVClicked();
    void onExportTextClicked();
    
    // Sniffer Slots
    void onPacketCaptured(PacketDataPtr packet);
    void onCaptureStarted();
    void onCaptureStopped();
    void onErrorOccurred(const QString& error);
    
    // Timer Slots
    void updateStatisticsTimer();
    
private:
    // UI Setup
    void setupUI();
    void createMenuBar();
    void createToolBar();
    void createSideMenu(); 
    void createCentralWidget();
    void loadDevices();
    
    // Helper functions
    void updatePacketDetailsUI(PacketDataPtr packet);
    void enableCaptureControls(bool capturing);
    void applyCurrentFilter();
    QString formatBytes(quint64 bytes);
    QString formatHexDump(const QByteArray& data);
    
    // MVP Pattern components
    std::shared_ptr<EventBus> m_eventBus;
    std::shared_ptr<IPacketRepository> m_repository;
    
    // UI Components
    QWidget* m_centralWidget;
    QVBoxLayout* m_mainLayout;
    
    // Toolbar buttons
    QPushButton* m_startButton;
    QComboBox* m_deviceCombo;
    QPushButton* m_stopButton;
    QPushButton* m_clearButton;
    
    // Packet Display
    QTableView* m_packetTable;
    QTabWidget* m_detailsTabs;
    QTextEdit* m_detailsText;
    QTextEdit* m_hexDumpText;
    
    // Filter UI
    QLineEdit* m_filterEdit;
    QComboBox* m_filterTypeCombo;
    QPushButton* m_clearFilterButton;
    
    // Statistics
    QLabel* m_packetsLabel;
    QLabel* m_displayedLabel;
    QLabel* m_statusLabel;
    
    // Data components
    PipeSnifferIntegrated* m_sniffer;
    PacketModel* m_model;
    QTimer* m_statsTimer;
    
    // Filter Delegate
    FilterDelegate* m_filterDelegate;
    
    // Side Menu
    QDockWidget* m_sideMenu;
    
    std::vector<PacketDataPtr> m_displayedPackets;
};

#endif // MAINWINDOW_H
