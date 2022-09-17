#ifndef KEEPASSXC_FDOSECRETSPLUGINCLI_H
#define KEEPASSXC_FDOSECRETSPLUGINCLI_H

#include "fdosecrets/FdoSecretsPlugin.h"

class LineReader;

class FdoSecretsPluginCLI : public FdoSecretsPlugin
{

public:
    FdoSecretsPluginCLI(LineReader* lineReader);
    ~FdoSecretsPluginCLI() override = default;

private:
    size_t requestEntriesRemove(const QSharedPointer<FdoSecrets::DBusClient>& client,
                                const QString& name,
                                const QList<Entry*>& entries,
                                bool permanent) const override;

    bool requestEntriesUnlock(const QSharedPointer<FdoSecrets::DBusClient>& client,
                              const QString&,
                              const QList<Entry*>& entries,
                              QHash<Entry*, AuthDecision>& decisions,
                              AuthDecision& forFutureEntries) const override;

    bool doLockDatabase(const QSharedPointer<FdoSecrets::DBusClient>&, const QString&) override
    {
        // Unsupported in CLI
        return false;
    }

    bool doUnlockDatabase(const QSharedPointer<FdoSecrets::DBusClient>&, const QString&) override
    {
        // Unsupported in CLI
        return false;
    }

    bool requestUnlockAnyDatabase(const QSharedPointer<FdoSecrets::DBusClient>&) const override
    {
        // Unsupported in CLI
        return false;
    }

    QString requestNewDatabase(const QSharedPointer<FdoSecrets::DBusClient>&) override
    {
        // Unsupported in CLI
        return {};
    }

    QString overrideMessageBoxParent(const QString&) const override
    {
        // Unsupported in CLI
        return {};
    }

    bool confirmDeleteEntries(const QSharedPointer<FdoSecrets::DBusClient>& client,
                              const QString& name,
                              const QList<Entry*>& entries,
                              bool permanent) const;

    int userAction(const QString& message, const QStringList& actions, const QStringList& matches) const;

private:
    LineReader* m_lineReader;
};

#endif // KEEPASSXC_FDOSECRETSPLUGINCLI_H
