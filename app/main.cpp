#include "mainwindow.h"
#include "eventbus.h"
#include "packet_repository.h"
#include <QApplication>
#include <QMessageBox>
#include <unistd.h>
#include <memory>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    // Create EventBus 
    auto eventBus = std::make_shared<EventBus>(false);  
    
    // Create Repository 
    std::shared_ptr<IPacketRepository> repository = std::make_shared<PacketRepository>();
    
    
    MainWindow window(eventBus, repository);
    window.show();
    
    return app.exec();
}

