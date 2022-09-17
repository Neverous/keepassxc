if(WITH_XC_SSHAGENT)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    set(sshagent_SOURCES
        ASN1Key.cpp
        BinaryStream.cpp
        KeeAgentSettings.cpp
        OpenSSHKey.cpp
        OpenSSHKeyGen.cpp
        SSHAgent.cpp
    )

    set(sshagent_gui_SOURCES
        AgentSettingsPage.cpp
        AgentSettingsWidget.cpp
        OpenSSHKeyGenDialog.cpp
    )

    add_library(sshagent STATIC ${sshagent_SOURCES})
    add_library(sshagent-gui STATIC ${sshagent_gui_SOURCES})
    target_link_libraries(sshagent Qt5::Core Qt5::Network)
    target_link_libraries(sshagent-gui sshagent Qt5::Widgets)
endif()
