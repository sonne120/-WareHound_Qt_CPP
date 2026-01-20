#include "mainwindow.h"
#include "filter_delegate.h"
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QScrollBar>
#include <QDockWidget>
#include <QMouseEvent>
#include <QDialog>

MainWindow::MainWindow(
    std::shared_ptr<EventBus> eventBus,
    std::shared_ptr<IPacketRepository> repository,
    QWidget *parent)
    : QMainWindow(parent)
    , m_eventBus(eventBus)
    , m_repository(repository)
    , m_sniffer(new PipeSnifferIntegrated(this))
    , m_model(new PacketModel(this))
    , m_statsTimer(new QTimer(this))
    , m_filterDelegate(new FilterDelegate(this)) {
    
    setupUI();
    
    connect(m_filterDelegate, &FilterDelegate::filterChanged,
            this, [this](const QString& filterText) {
                m_model->setFilter(filterText);
                applyCurrentFilter();
            });

    connect(m_sniffer, &PipeSnifferIntegrated::packetCaptured,
            this, &MainWindow::onPacketCaptured);
    connect(m_sniffer, &PipeSnifferIntegrated::captureStarted,
            this, &MainWindow::onCaptureStarted);
    connect(m_sniffer, &PipeSnifferIntegrated::captureStopped,
            this, &MainWindow::onCaptureStopped);
    connect(m_sniffer, &PipeSnifferIntegrated::errorOccurred,
            this, &MainWindow::onErrorOccurred);
    
    connect(m_statsTimer, &QTimer::timeout, this, &MainWindow::updateStatisticsTimer);
    m_statsTimer->setInterval(1000);
    
    loadDevices();
}

MainWindow::~MainWindow() {
    m_sniffer->stopCapture();
    }

void MainWindow::setupUI() {
    setWindowTitle("WireHound");
    resize(1200, 800);
    
    createSideMenu();
    createToolBar();
    createCentralWidget();
    
    // Status bar
    statusBar()->showMessage("Ready");
}

void MainWindow::createSideMenu() {
    m_sideMenu = new QDockWidget("Menu", this);
    m_sideMenu->setAllowedAreas(Qt::LeftDockWidgetArea);
    m_sideMenu->setFeatures(QDockWidget::NoDockWidgetFeatures);
    

    QWidget* emptyTitle = new QWidget();
    m_sideMenu->setTitleBarWidget(emptyTitle);

    QWidget* menuWidget = new QWidget();

    menuWidget->setStyleSheet("background-color: #f5f5f5;"); 
    
    QVBoxLayout* layout = new QVBoxLayout(menuWidget);
    layout->setContentsMargins(0, 20, 0, 0);
    layout->setSpacing(5);
    layout->setAlignment(Qt::AlignTop);

    auto createMenuBtn = [this, layout](const QString& text, std::function<void()> slot) {
        QPushButton* btn = new QPushButton(text);
        btn->setStyleSheet(
            "QPushButton { "
            "  text-align: left; "
            "  padding: 15px 20px; "
            "  border: none; "
            "  background: transparent; "
            "  font-size: 14px; "
            "  color: #333; "
            "}"
            "QPushButton:hover { "
            "  background-color: #e0e0e0; "
            "}"
        );
        btn->setCursor(Qt::PointingHandCursor);
        connect(btn, &QPushButton::clicked, this, [this, slot]() {
            slot();
            // m_sideMenu->hide()
        });
        layout->addWidget(btn);
    };

    // Header label
    QLabel* title = new QLabel("   WireHound Menu");
    title->setStyleSheet("font-weight: bold; font-size: 16px; color: #555; margin-bottom: 20px;");
    layout->addWidget(title);

    createMenuBtn("  Start Capture", [this](){ onStartCaptureClicked(); });
    createMenuBtn("  Stop Capture", [this](){ onStopCaptureClicked(); });
    createMenuBtn("  Clear Packets", [this](){ onClearPacketsClicked(); });
    
    QFrame* line1 = new QFrame();
    line1->setFrameShape(QFrame::HLine);
    line1->setStyleSheet("color: #ccc; background-color: #ccc; margin: 10px 0;");
    line1->setFixedHeight(1);
    layout->addWidget(line1);

    createMenuBtn("  Export CSV...", [this](){ onExportCSVClicked(); });
    createMenuBtn("  Export Text...", [this](){ onExportTextClicked(); });

    QFrame* line2 = new QFrame();
    line2->setFrameShape(QFrame::HLine);
    line2->setStyleSheet("color: #ccc; background-color: #ccc; margin: 10px 0;");
    line2->setFixedHeight(1);
    layout->addWidget(line2);
    createMenuBtn("  About", [this]() {
      QMessageBox::about(this, "About WireHound",
                          "<h3>WireHound v1.0</h3>"
                          "<p>High-performance network packet analyzer.</p>"
                          "<p>Built with <b>Qt 6</b> and <b>libpcap</b>.</p>"
                          "<p>Architecture: Producer-Consumer via Pipes.</p>");
    });

    // Spacer
    layout->addStretch();
    
    createMenuBtn("  Exit", [this](){ close(); });

    m_sideMenu->setWidget(menuWidget);
    addDockWidget(Qt::LeftDockWidgetArea, m_sideMenu);
    m_sideMenu->hide(); 
}

void MainWindow::createMenuBar() {
    QMenuBar* menuBar = new QMenuBar(this);

    menuBar->setNativeMenuBar(false); 

    setMenuBar(menuBar);
    
    // File menu
    QMenu* fileMenu = menuBar->addMenu("&File");
    
    QIcon csvIcon = QIcon::fromTheme("text-csv"); 
    QAction* exportCSVAction = fileMenu->addAction(csvIcon, "Export to &CSV...");
    exportCSVAction->setShortcut(QKeySequence("Ctrl+E"));
    exportCSVAction->setStatusTip("Export captured packets to a CSV file");
    connect(exportCSVAction, &QAction::triggered, this, &MainWindow::onExportCSVClicked);
    
    QIcon txtIcon = QIcon::fromTheme("text-plain");
    QAction* exportTextAction = fileMenu->addAction(txtIcon, "Export to &Text...");
    exportTextAction->setShortcut(QKeySequence("Ctrl+Shift+E"));
    exportTextAction->setStatusTip("Export captured packets to a text report");
    connect(exportTextAction, &QAction::triggered, this, &MainWindow::onExportTextClicked);
    
    fileMenu->addSeparator();
    
    QAction* exitAction = fileMenu->addAction("E&xit");
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    
    // View Menu
    QMenu* viewMenu = menuBar->addMenu("&View");
    
    // Help menu
    QMenu* helpMenu = menuBar->addMenu("&Help");
    
    QAction* aboutAction = helpMenu->addAction("&About WireHound");
    connect(aboutAction, &QAction::triggered, [this]() {
        QMessageBox::about(this, "About WireHound",
                          "<h3>WireHound v1.0</h3>"
                          "<p>High-performance network packet analyzer.</p>"
                          "<p>Built with <b>Qt 6</b> and <b>libpcap</b>.</p>"
                          "<p>Architecture: Producer-Consumer via Pipes.</p>");
    });
}

void MainWindow::createToolBar() {
    QToolBar* toolBar = addToolBar("Main Toolbar");
    toolBar->setMovable(false);
    

    // Hamburger Menu Button
    QPushButton* menuBtn = new QPushButton("☰");
    menuBtn->setToolTip("Toggle Menu");
    menuBtn->setFlat(true);
    // Increase font size as requested
    menuBtn->setStyleSheet("font-size: 24px; font-weight: bold; border: none; padding: 5px;");
    menuBtn->setCursor(Qt::PointingHandCursor);
    toolBar->addWidget(menuBtn);

    QWidget* emptySpacer = new QWidget();
    emptySpacer->setFixedWidth(10);
    toolBar->addWidget(emptySpacer);
    
    // Toggle side menu visibility
    connect(menuBtn, &QPushButton::clicked, this, [this]() {
        if (m_sideMenu->isHidden()) {
            m_sideMenu->show();
        } else {
            m_sideMenu->hide();
        }
    });

    toolBar->addSeparator();

    // Device selection
    toolBar->addWidget(new QLabel("Device: "));
    m_deviceCombo = new QComboBox();
    m_deviceCombo->setMinimumWidth(250);
    toolBar->addWidget(m_deviceCombo);
    toolBar->addSeparator();

    m_startButton = new QPushButton("Start Capture");
    m_stopButton = new QPushButton("Stop Capture");
    m_clearButton = new QPushButton("Clear");
    
    toolBar->addWidget(m_startButton);
    toolBar->addWidget(m_stopButton);
    toolBar->addSeparator();
    toolBar->addWidget(m_clearButton);
    
    connect(m_startButton, &QPushButton::clicked, this, &MainWindow::onStartCaptureClicked);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWindow::onStopCaptureClicked);
    connect(m_clearButton, &QPushButton::clicked, this, &MainWindow::onClearPacketsClicked);
    
    m_stopButton->setEnabled(false);
}

void MainWindow::createCentralWidget() {
    m_centralWidget = new QWidget(this);
    setCentralWidget(m_centralWidget);
    
    m_mainLayout = new QVBoxLayout(m_centralWidget);
    
    // Filter Bar (Delegate Pattern)
    QHBoxLayout* filterLayout = new QHBoxLayout();
    
    QLabel* filterLabel = new QLabel("Filter:");
    m_filterEdit = new QLineEdit();
    m_filterEdit->setPlaceholderText("Enter filter (e.g., tcp, 192.168, port 80, ip.src == 10.0.0.1)");
    m_filterEdit->setClearButtonEnabled(true);
    
    m_filterTypeCombo = new QComboBox();
    m_filterTypeCombo->addItem("Simple", static_cast<int>(FilterDelegate::FilterType::Simple));
    m_filterTypeCombo->addItem("Protocol", static_cast<int>(FilterDelegate::FilterType::Protocol));
    m_filterTypeCombo->addItem("IP Address", static_cast<int>(FilterDelegate::FilterType::IP));
    m_filterTypeCombo->addItem("Port", static_cast<int>(FilterDelegate::FilterType::Port));
    m_filterTypeCombo->addItem("Host Name", static_cast<int>(FilterDelegate::FilterType::HostName));
    m_filterTypeCombo->addItem("Advanced", static_cast<int>(FilterDelegate::FilterType::Advanced));
    m_filterTypeCombo->setToolTip("Select filter type");
    
    m_clearFilterButton = new QPushButton("Clear");
    m_clearFilterButton->setToolTip("Clear filter");
    
    filterLayout->addWidget(filterLabel);
    filterLayout->addWidget(m_filterEdit, 1);  // Stretch
    filterLayout->addWidget(m_filterTypeCombo);
    filterLayout->addWidget(m_clearFilterButton);
    
    m_mainLayout->addLayout(filterLayout);
    
    connect(m_filterEdit, &QLineEdit::textChanged,
            this, &MainWindow::onFilterChangedUI);
    connect(m_filterTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int index) {
                auto type = static_cast<FilterDelegate::FilterType>(m_filterTypeCombo->itemData(index).toInt());
                m_filterDelegate->setFilterType(type);
                m_filterDelegate->setFilterText(m_filterEdit->text());
            });
    connect(m_clearFilterButton, &QPushButton::clicked,
            this, [this]() {
                m_filterEdit->clear();
                m_filterDelegate->clear();
            });
    
    QSplitter* splitter = new QSplitter(Qt::Vertical);
    
    // Packet Table
    m_packetTable = new QTableView();
    m_packetTable->setModel(m_model);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_packetTable->setAlternatingRowColors(true);
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->verticalHeader()->setVisible(false);
    
    // Set column widths
    m_packetTable->setColumnWidth(PacketModel::Number, 80);
    m_packetTable->setColumnWidth(PacketModel::Time, 120);
    m_packetTable->setColumnWidth(PacketModel::SourceIP, 150);
    m_packetTable->setColumnWidth(PacketModel::DestIP, 150);
    m_packetTable->setColumnWidth(PacketModel::Protocol, 100);
    m_packetTable->setColumnWidth(PacketModel::Length, 80);

    

    m_packetTable->setMinimumHeight(200);
    m_packetTable->horizontalHeader()->setVisible(true);
    m_packetTable->setSortingEnabled(false);
    m_packetTable->setShowGrid(true);
    
    connect(m_packetTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onPacketSelectedUI);
            
    connect(m_packetTable, &QTableView::doubleClicked,
            this, &MainWindow::onPacketDoubleClicked);
    
    splitter->addWidget(m_packetTable);
    

    m_detailsTabs = new QTabWidget();
    
    m_detailsText = new QTextEdit();
    m_detailsText->setReadOnly(true);
    m_detailsText->setFont(QFont("Courier", 12));
    
    m_hexDumpText = new QTextEdit();
    m_hexDumpText->setReadOnly(true);
    m_hexDumpText->setFont(QFont("Courier", 12));
    
    m_detailsTabs->addTab(m_detailsText, "Packet Details");
    m_detailsTabs->addTab(m_hexDumpText, "Hex Dump");
    
    splitter->addWidget(m_detailsTabs);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);
    
    m_mainLayout->addWidget(splitter);
    
    
    // Statistics Bar
    QHBoxLayout* statsLayout = new QHBoxLayout();
    
    m_packetsLabel = new QLabel("Packets: 0");
    m_displayedLabel = new QLabel("Displayed: 0");
    m_statusLabel = new QLabel("Status: Ready");
    
    statsLayout->addWidget(m_packetsLabel);
    statsLayout->addWidget(m_displayedLabel);
    statsLayout->addStretch();
    statsLayout->addWidget(m_statusLabel);
    
    m_mainLayout->addLayout(statsLayout);
}

void MainWindow::loadDevices() {
    m_deviceCombo->clear();
    QStringList devices = m_sniffer->getDeviceList();
    
    if (devices.isEmpty()) {
        m_deviceCombo->addItem("No devices found");
        m_deviceCombo->setEnabled(false);
        m_startButton->setEnabled(false);
    } else {
        m_deviceCombo->addItems(devices);
        m_deviceCombo->setEnabled(true);
        m_startButton->setEnabled(true);

        if (m_deviceCombo->count() > 0)
             m_deviceCombo->setCurrentIndex(0);
    }
    
    m_statusLabel->setText("Status: Ready");
}


void MainWindow::enableCaptureControls(bool capturing) {
    m_startButton->setEnabled(!capturing);
    m_stopButton->setEnabled(capturing);
}

void MainWindow::applyCurrentFilter() {
    std::vector<PacketDataPtr> filtered;
    
    auto allPackets = m_repository->getAll();
    
    for (const auto& packet : allPackets) {
        if (m_filterDelegate->matches(packet)) {
            filtered.push_back(packet);
        }
    }
    
    // Update displayed packets
    m_displayedPackets = filtered;
    m_model->setPackets(filtered);
    
    // Update statistics
    m_packetsLabel->setText(QString("Packets: %1").arg(allPackets.size()));
    m_displayedLabel->setText(QString("Displayed: %1").arg(filtered.size()));
}

QString MainWindow::formatBytes(quint64 bytes) {
    const quint64 KB = 1024;
    const quint64 MB = KB * 1024;
    const quint64 GB = MB * 1024;
    
    if (bytes >= GB) {
        return QString("%1 GB").arg(bytes / (double)GB, 0, 'f', 2);
    } else if (bytes >= MB) {
        return QString("%1 MB").arg(bytes / (double)MB, 0, 'f', 2);
    } else if (bytes >= KB) {
        return QString("%1 KB").arg(bytes / (double)KB, 0, 'f', 2);
    } else {
        return QString("%1 B").arg(bytes);
    }
}

QString MainWindow::formatHexDump(const QByteArray& data) {
    QString result;
    const int bytesPerLine = 16;

    for (int i = 0; i < data.size(); i += bytesPerLine) {
        // Offset (8 hex digits for safety)
        result += QString("%1  ").arg(i, 8, 16, QChar('0')).toUpper();

        // Hex values
        for (int j = 0; j < bytesPerLine; ++j) {
            if (i + j < data.size()) {
                result += QString("%1 ").arg((unsigned char)data[i + j], 2, 16, QChar('0')).toUpper();
            } else {
                result += "   ";
            }
            if (j == 7) result += " ";
        }

        result += " ";

        // ASCII representation
        for (int j = 0; j < bytesPerLine && (i + j) < data.size(); ++j) {
            unsigned char c = data[i + j];
            result += (c >= 32 && c <= 126) ? QChar(c) : QChar('.');
        }

        result += "\n";
    }

    return result;
}

void MainWindow::displayPackets(const std::vector<PacketDataPtr>& packets) {

    size_t currentSize = m_displayedPackets.size();
    size_t newSize = packets.size();
    
    if (newSize > currentSize && newSize < currentSize + 10) {
        for (size_t i = currentSize; i < newSize; ++i) {
            m_model->addPacket(packets[i]);
        }
        m_displayedPackets = packets;
        m_packetTable->scrollToBottom();
        return;
    }
    
    m_displayedPackets = packets;
    m_model->setPackets(packets);
    
    if (!packets.empty()) {
        m_packetTable->scrollToBottom();
    }
}

void MainWindow::displayPacketDetails(const PacketDataPtr& packet) {
    updatePacketDetailsUI(packet);
}

void MainWindow::setDeviceList(const std::vector<std::string>& devices) {
    Q_UNUSED(devices)
}

void MainWindow::updateStatistics(int totalPackets, int displayedPackets, uint64_t totalBytes) {
    m_packetsLabel->setText(QString("Total: %1").arg(totalPackets));
    m_displayedLabel->setText(QString("Displayed: %1 (%2)")
                              .arg(displayedPackets)
                              .arg(formatBytes(totalBytes)));
}

void MainWindow::setCaptureState(bool capturing) {
    enableCaptureControls(capturing);
    if (capturing) {
        m_statsTimer->start();
    } else {
        m_statsTimer->stop();
    }
}

void MainWindow::showMessage(const std::string& message) {
    QString qmsg = QString::fromStdString(message);
    m_statusLabel->setText("Status: " + qmsg);
    statusBar()->showMessage(qmsg);
}

void MainWindow::showError(const std::string& error) {
    QMessageBox::warning(this, "Error", QString::fromStdString(error));
}

void MainWindow::onStartCaptureClicked() {

    int deviceNumber = m_deviceCombo->currentIndex() + 1;
    
    if (deviceNumber <= 0) deviceNumber = 1;
    
    m_sniffer->startCapture(deviceNumber);
}

void MainWindow::onStopCaptureClicked() {
    m_sniffer->stopCapture();
}

void MainWindow::onClearPacketsClicked() {
    m_model->clear();
    m_displayedPackets.clear();
    m_repository->clear();
    statusBar()->showMessage("Packets cleared");
}

void MainWindow::onDeviceChangedUI(int index) {
    Q_UNUSED(index)
}

void MainWindow::onFilterChangedUI(const QString& text) {
    m_filterDelegate->setFilterText(text);
}

void MainWindow::onPacketSelectedUI(const QModelIndex& index) {
    if (!index.isValid()) {
        return;
    }
    
    int row = index.row();
    PacketDataPtr packet = m_model->getPacket(row);
    if (packet) {
        updatePacketDetailsUI(packet);
        updatePacketDetailsUI(packet);
    }
}

void MainWindow::onExportCSVClicked() {
    QString filename = QFileDialog::getSaveFileName(this, "Export to CSV",
                                                    QDir::homePath() + "/packets.csv", 
                                                    "CSV Files (*.csv)");
    if (filename.isEmpty()) {
        return;
    }

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing: " + file.errorString());
        return;
    }

    QTextStream out(&file);
    // Write Header
    out << "No.,Time,Source,Destination,Protocol,Length,Info\n";

    // Write Data from the current view model
    int rows = m_model->rowCount();
    for (int i = 0; i < rows; ++i) {
        auto packet = m_model->getPacket(i);
        if (!packet) continue;

        out << packet->packetNumber << ","
            << packet->timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz") << ","
            << packet->sourceIP << ","
            << packet->destIP << ","
            << packet->protocol << ","
            << packet->length << ","
            << "\"" << packet->info.replace("\"", "\"\"") << "\"\n";
    }

    file.close();
    statusBar()->showMessage(QString("Exported %1 packets to CSV").arg(rows), 3000);
}

void MainWindow::onExportTextClicked() {
    QString filename = QFileDialog::getSaveFileName(this, "Export to Text",
                                                    QDir::homePath() + "/packets.txt", 
                                                    "Text Files (*.txt)");
    if (filename.isEmpty()) {
        return;
    }

    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export Error", "Could not open file for writing: " + file.errorString());
        return;
    }

    QTextStream out(&file);
    out << "Packet Capture Report\n";
    out << "Generated: " << QDateTime::currentDateTime().toString() << "\n";
    out << "Total Packets: " << m_model->rowCount() << "\n";
    out << "================================================================================\n\n";

    int rows = m_model->rowCount();
    for (int i = 0; i < rows; ++i) {
        auto packet = m_model->getPacket(i);
        if (!packet) continue;

        out << QString("Packet #%1\n").arg(packet->packetNumber);
        out << QString("Time:      %1\n").arg(packet->timestamp.toString("hh:mm:ss.zzz"));
        out << QString("Protocol:  %1\n").arg(packet->protocol);
        out << QString("Source:    %1:%2 (%3)\n").arg(packet->sourceIP).arg(packet->sourcePort).arg(packet->sourceMac);
        out << QString("Dest:      %1:%2 (%3)\n").arg(packet->destIP).arg(packet->destPort).arg(packet->destMac);
        out << QString("Length:    %1 bytes\n").arg(packet->length);
        out << QString("Info:      %1\n").arg(packet->info);
        out << "--------------------------------------------------------------------------------\n";
    }

    file.close();
    statusBar()->showMessage(QString("Exported %1 packets to Text").arg(rows), 3000);
}
void MainWindow::onPacketCaptured(PacketDataPtr packet) {
    m_model->addPacket(packet);
    
    m_displayedPackets.push_back(packet);
    
    m_repository->add(packet);
    
    m_eventBus->publish(Event(EventType::PacketCaptured, packet));
}

void MainWindow::onCaptureStarted() {
    enableCaptureControls(true);
    m_statsTimer->start();
    statusBar()->showMessage("Capturing packets...");
    m_eventBus->publish(Event(EventType::CaptureStarted));
}

void MainWindow::onCaptureStopped() {
    enableCaptureControls(false);
    m_statsTimer->stop();
    statusBar()->showMessage("Capture stopped");
    m_eventBus->publish(Event(EventType::CaptureStopped));
}

void MainWindow::onErrorOccurred(const QString& error) {
    m_eventBus->publish(Event(EventType::CaptureError, error.toStdString()));
}

void MainWindow::updateStatisticsTimer() {

    int totalPackets = static_cast<int>(m_sniffer->getPacketCount());
    int displayedPackets = m_model->rowCount();
    
    m_packetsLabel->setText(QString("Total: %1").arg(totalPackets));
    m_displayedLabel->setText(QString("Displayed: %1").arg(displayedPackets));
}

void MainWindow::updatePacketDetailsUI(PacketDataPtr packet) {

    QString details;
    details += QString("Packet #%1\n").arg(packet->packetNumber);
    details += QString("Time: %1\n").arg(packet->timestamp.toString());
    details += QString("Length: %1 bytes\n\n").arg(packet->length);
    
    details += "Source:\n";
    details += QString("  IP: %1\n").arg(packet->srcIp);
    details += QString("  Port: %1\n").arg(packet->srcPort);
    details += QString("  MAC: %1\n\n").arg(packet->srcMac);
    
    details += "Destination:\n";
    details += QString("  IP: %1\n").arg(packet->dstIp);
    details += QString("  Port: %1\n").arg(packet->dstPort);
    details += QString("  MAC: %1\n\n").arg(packet->dstMac);
    
    details += QString("Protocol: %1\n").arg(packet->protocol);
    details += QString("Host Name: %1\n").arg(packet->hostName);
    details += QString("Info: %1\n").arg(packet->info);
    
    m_detailsText->setText(details);
    
    // Hex dump
    m_hexDumpText->setText(formatHexDump(packet->rawData));
}

void MainWindow::onPacketDoubleClicked(const QModelIndex& index) {
    if (!index.isValid()) return;
    
    int row = index.row();
    PacketDataPtr packet = m_model->getPacket(row);
    if (!packet) return;
    
    QDialog* dialog = new QDialog(this);
    dialog->setWindowTitle(QString("Packet #%1 Details").arg(packet->packetNumber));
    dialog->resize(700, 600);
    
    QVBoxLayout* layout = new QVBoxLayout(dialog);
    
    QTextEdit* textEdit = new QTextEdit(dialog);
    textEdit->setReadOnly(true);
    QFont font("Courier");
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    textEdit->setFont(font);
    
    QString details;
    details += QString("Packet #%1\n").arg(packet->packetNumber);
    details += QString("Time:   %1\n").arg(packet->timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"));
    details += QString("Length: %1 bytes\n").arg(packet->length);
    details += "--------------------------------------------------\n";
    
    details += "Source:\n";
    details += QString("  IP:   %1\n").arg(packet->srcIp);
    details += QString("  Port: %1\n").arg(packet->srcPort);
    details += QString("  MAC:  %1\n\n").arg(packet->srcMac);
    
    details += "Destination:\n";
    details += QString("  IP:   %1\n").arg(packet->dstIp);
    details += QString("  Port: %1\n").arg(packet->dstPort);
    details += QString("  MAC:  %1\n").arg(packet->dstMac);
    
    details += "--------------------------------------------------\n";
    details += QString("Protocol: %1\n").arg(packet->protocol);
    details += QString("Host Name: %1\n").arg(packet->hostName);
    details += QString("Info:     %1\n").arg(packet->info);
    details += "--------------------------------------------------\n";
    details += "Hex Dump:\n\n";
    details += formatHexDump(packet->rawData);
    
    textEdit->setPlainText(details);
    
    layout->addWidget(textEdit);
    
    QPushButton* closeBtn = new QPushButton("Close", dialog);
    connect(closeBtn, &QPushButton::clicked, dialog, &QDialog::accept);
    layout->addWidget(closeBtn, 0, Qt::AlignCenter);
    
    dialog->exec();
}
