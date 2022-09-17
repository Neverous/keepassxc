if(WITH_XC_FDOSECRETS)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    add_library(fdosecrets STATIC
        FdoSecretsPlugin.cpp

        # setting storage
        FdoSecretsSettings.cpp

        # D-Bus objects
        dbus/DBusClient.cpp
        dbus/DBusMgr.cpp
        dbus/DBusDispatch.cpp
        dbus/DBusObject.cpp
        objects/Service.cpp
        objects/Session.cpp
        objects/SessionCipher.cpp
        objects/Collection.cpp
        objects/Item.cpp
        objects/Prompt.cpp
        dbus/DBusTypes.cpp
    )
    target_link_libraries(fdosecrets Qt5::Core Qt5::DBus ${BOTAN_LIBRARIES})

    add_library(fdosecrets-cli STATIC
        FdoSecretsPluginCLI.cpp
    )
    target_link_libraries(fdosecrets-cli fdosecrets)

    add_library(fdosecrets-gui STATIC
        FdoSecretsPluginGUI.cpp

        # app settings page
        FdoSecretsSettingsPage.cpp
        widgets/SettingsModels.cpp
        widgets/SettingsWidgetFdoSecrets.cpp
        widgets/RowButtonHelper.cpp

        # per database settings page
        widgets/DatabaseSettingsWidgetFdoSecrets.cpp

        # prompt dialog
        widgets/AccessControlDialog.cpp
    )
    target_link_libraries(fdosecrets-gui fdosecrets Qt5::Widgets)
endif()
